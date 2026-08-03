# #6751 plan — interface SNAT no-PAT admission: reserve-or-PAT the colliding translated tuple

- **Status**: DRAFT v15.6 — round-19 fold (Codex r19 blocker 1 + minor 2
  + nit 3: the generation-fenced abort transition is now NORMATIVE in
  §5.6 with six contract clauses — atomic abort-generation fence state,
  installConn ADMITTED/REFUSED verdicts with refused connections closed
  without any pending-frame/loop/callback/cold-prime work,
  install-before-dispatch for the pending first frame, COMMIT-TIME
  generation validation at every stateful frame application (closing
  the pass-check-then-stall race), reset-once ownership with nested-
  abort re-arm semantics, and receiver-local peer convergence; the
  capability transport is the dedicated ticker alone; §5.8 names the
  overflow counter explicitly)
- **Issue**: #6751 (opus-review-001 R08, High, `bug`+`audit`+`security`) —
  interface SNAT admits indistinguishable no-PAT return tuples and sends
  replies to the FIRST session.
- **Base**: `ad9591177481` (origin/master at research start).
- **Scope**: `userspace-dp` Rust dataplane + Go snapshot-builder overlap
  foreclosure + Go commit-validator extension (§5.7) + additive optional
  status counters (§5.8). No breaking wire change, no `NatDecision`/
  `SourceNatLookup` shape change.
- **Core invariant** (round-3/4 reviewers' formulation, adopted): EVERY
  reachable session owns exactly one translated identity, held continuously
  from before it is reachable until after it is not — across admission,
  publication, replication, materialization, tuple-changing re-sync,
  reconcile replay, snapshot rebuilds, drain transitions, HA transitions,
  link stop→rebind cycles, worker teardown, and helper restart. Scoped
  (SMR r5 N16): the queue/relay-or-expiry-bounded reverse-companion edge
  is excluded — identical in shape to shipped pool-mode discipline today;
  see §5.6.

---

## 1. Issue framing

Interface-mode source NAT (`set security nat source rule-set RS rule R then
source-nat interface`) rewrites the source ADDRESS to the egress interface's
own address and PRESERVES the source port (`nat/source.rs:1226-1251`). It
mints no allocation, no reservation, no occupancy token of any kind. Two
internal hosts that pick the same source port to the same server:port over the
same protocol therefore produce ONE external five-tuple:

```
H1 10.0.0.1:5555 -> S:80  --(iface SNAT to E)-->  E:5555 -> S:80
H2 10.0.0.2:5555 -> S:80  --(iface SNAT to E)-->  E:5555 -> S:80   (same tuple)
reverse wire key for both: (S:80 -> E:5555)
```

The #4399/#4438 1:N multimaps keep BOTH forward handles in the reverse-key
bucket, but candidate validation
(`reply_matches_forward_session`, `session/key.rs:19`) recomputes the SAME
translated tuple for both sessions, so both validate and
`find_forward_nat_match` (`session/lookup.rs:222`) returns the first-installed
handle deterministically. `install_reverse_session_from_forward_match`
(`afxdp/session_glue/mod.rs:1294`) then derives the reverse rewrite/delivery
from that handle: every reply for the ambiguous tuple is un-NAT'd to H1 — a
cross-session data leak (H2's return traffic delivered to H1) with
wrong-session reset/state damage projected for both flows (the pinned tests
prove the misdelivery; the packet-level RST lifecycle is inferred, and the §9
smoke test will demonstrate it). On the cross-worker shared maps
(`afxdp/shared_ops.rs:897` `publish_shared_session`) the collision is worse:
`shared_nat_sessions` is single-value, so the second publish DISPLACES the
first (counted by `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS`) and which host wins
depends on RSS worker topology — non-deterministic per-flow hijack. No packet
field can disambiguate after admission: the reply `(S:80 -> E:5555)` carries
zero identifying header fields, and no index (SessionKey/NatDecision/metadata)
holds inner-host, ingress-ifindex, zone, or VRF context on the reverse path
(#2387, open, is exactly that gap).

The production test suite PINS the misdelivery:
`session/tests.rs:4560` (`nat_reverse_1n_collision_preserves_displaced_return_path`)
constructs exactly this two-host interface-SNAT collision and at
`session/tests.rs:4602-4610` asserts the reply resolves to the FIRST-installed
session because "the wire tuple is genuinely ambiguous under no-PAT interface
SNAT". The codebase encodes the bug as expected behavior.

## 2. Honest scope/value framing

This is a correctness/security fix, not a performance change. The absolute
win:

- Eliminates a silent cross-session data leak (one internal host receives
  another host's return traffic — confidentiality/integrity violation on a
  box whose job is traffic separation), the wrong-session state damage, and
  the non-deterministic shared-map displacement variant.
- Narrows a Junos-parity gap: official Juniper documentation states that
  interface NAT always performs PAT (Codex r2, citing Juniper's Source NAT
  topic map), and the Junos grammar carries `security nat source interface
  port-overloading off` to tune interface-mode port REUSE (in-repo: #4291
  records the knob accepted-and-advisory at
  pkg/config/compiler_nat_source.go:253-271). xpf's port-preserving
  interface mode is the outlier. Preserve-first + PAT-on-collision (§4) is
  an INTENTIONAL xpf semantic — wire-stable for non-colliding flows — not
  claimed literal Junos parity (Junos allocates unconditionally).
- Collision frequency today: requires same protocol + same source port +
  same server + simultaneous liveness. Rare for random-ephemeral TCP, but
  realistic for ICMP echo (Linux ping reuses small per-socket identifiers),
  for UDP services with pinned source ports, and for any middlebox that
  normalizes source ports. It is also a deterministic insider primitive
  (deliberate squatting; UDP/ICMP need no handshake).

If reviewers conclude the fix's churn exceeds the risk, PLAN-KILL is an
acceptable verdict — PLAN-KILL here means shipping option (c), status quo
plus documentation, and saying so on the issue.

## 3. What's already shipped / partially batched

| Prior work | What it gives this plan |
|---|---|
| #4399/#4438 1:N multimaps + validate-on-lookup | Defense-in-depth retention for the OTHER non-bijective classes (DNAT-shared-backend, NAT64, static). |
| **#5269/#5336/#5338/#5341/#6041/#6226** address-only occupancy token (`reserve_address_only`, `address_only_owners`, `release_flow`/`rollback_flow` address_only arm, `reserve_flow` stale-tuple-drop at allocator.rs:1666-1676) | THE mechanism option (a) is built on: identity-keyed occupancy `(protocol, translated_ip, translated_port, dst_ip, dst_port)`, ONE-mutex mint, idempotent re-entry, fail-closed collision. Preserve AND PAT both mint this token shape; release/rollback verbatim (allocator.rs:1318/1392). |
| #5144 strict overlap validator (compiler_validate_strict_nat.go:2525-2576) + `pool_failure`/`PoolUnusable` channel (nat_source.go:118-122; NAT64 native empty-pool fail-closed at nat64.rs:1123) | The two-layer foreclosure pattern §5.7 extends. |
| #4388/#4512 synced reserve + coordinator publish path (ha/session_import.rs) | The HA reservation points §5.6 makes transactional. |
| #4518 NAT64 allocator carry-over across reloads | The drain-domain retention precedent for §5.7. |
| #4074/#4088 ICMP id translation; #1852 + #2562/#5146 + #6122 fragment machinery | The ICMP/fragment stories, unchanged. |
| #4676 `gc_expired_chunked` | The §4.3 probe chunking discipline. |
| SessionManager coordinator-owned shared maps (coordinator/session_manager.rs:12 → worker/launch.rs:130) | The registry placement precedent. |
| #1760 W3' status-counter plumbing (protocol/control.rs:343, coordinator/status.rs:241, server/lifecycle.rs:228, server/helpers/status.rs:102, protocol_status.go:287, pkg/api/metrics.go:377/791, metrics_descriptors_userspace_session.go:27, metrics_userspace.go:677) | The additive-counters precedent §5.8 follows — full inventory (Codex r3 major 7 + r4 minor 9). |
| **OPEN #6522** — sibling replica reap releases a live flow's SNAT allocation | The new registry's holder model (§5.6) is designed so this hazard cannot exist in it; pool-side fix remains #6522's own issue. |

## 4. Multiple Path Options (the design fork)

### Option (a) — reserve translated identity at admission; PAT the later collider (RECOMMENDED)

Interface-mode becomes "address-only occupancy with preserve-first and an
exact PAT fallback", built ENTIRELY on the shipped #5269 token machinery:

1. **Registry (node-lifetime, OUTSIDE ForwardingState)** — coordinator-owned
   next to the shared session maps (`SessionManager`), cloned into every
   worker (`WorkerSharedDataplane::from_coord`). Never rebuilt on commit;
   one `Arc<PortAllocator>` per egress address. `allocator_for` is ONE
   write-lock `entry(addr).or_insert_with(...)` returning the stored winner.
   Bounded lifetime: apply-time reclamation (address absent from the new
   egress set AND `live_by_flow` empty) + opportunistic reclaim when a
   release empties an absent allocator; a cap of 256 CURRENTLY-RETAINED
   allocators (retained cardinality, NOT ever-created — its own failure
   surface per §5.8); RELEASE is LOOKUP-ONLY (`allocator_if_present`).
2. **Occupancy model (identity-set, no bitmap claims)** — occupancy keyed on
   the FULL reverse identity `(protocol, egress_addr, port, dst_ip,
   dst_port)` (the shipped `AddressOnlyReverseKey`, allocator.rs:178-183):
   same source port to different servers → BOTH preserve; TCP vs UDP same
   numeric port → both preserve; source port < 1024 → preserved (PAT
   candidates drawn ≥ 1024); cross-destination port reuse allowed (the
   Junos-default OVERLOADING posture).
3. **Admission mint** (interface branch, nat/source.rs:1226), gated
   `!non_first_fragment && !tuple_unknown` (BOTH probe classes mint nothing):
   - **port-less protocol**: `alloc.reserve_address_only(flow, egress)` —
     Ok → Matched (address-only); Err → `Unavailable(AllocatorExhausted)`.
   - **port-bearing**: per-step single-mutex CS — (i) idempotent re-entry;
     (ii) identity-mint the PRESERVED tuple → `rewrite_src_port: None`;
     (iii) identity held by a different flow → EXACT PAT probe: capture ONE
     start ordinal from the allocator's atomic cursor, walk
     `start + i mod 64512` LOCALLY (never re-calling the shared cursor
     mid-walk), identity-minting per candidate, at most 64 candidates per
     `live` mutex acquisition with yields between (#4676). A full cycle
     with no success = exhaustion, two modes distinguished by counter
     (§5.8): per-(egress,dst,dport) identity space full, OR the per-address
     `live_by_flow` registry cap (64512) consumed by flows to OTHER
     destinations. ONE mutation-epoch retry (re-walk once if the epoch
     advanced mid-walk); a second failure is documented exhaustion-under-
     churn (the linearizability boundary AGY r3 verified).
   - Preserved and PAT'd tokens share the SAME `address_only` record shape
     and the SAME release/rollback arms. No lock-free pre-claim exists.
4. **No session-index, lookup, flow-cache, or packet-rewrite changes** —
   identities unique per flow ⟹ the bijective fast path is correct; NO
   longer packet-path scan (per the review's guidance). Surface audit
   (verified POSITIVE by AGY r2 + Codex r2/r3/r4):
   `rewrite_src_port: Some(_)` is already generic from pool mode on
   flow-cache descriptors (flow_cache.rs:586), conntrack publish
   (publish_conntrack.rs:197), gRPC render (server_sessions.go:1724),
   RT_FLOW (rt_flow.rs:82), HA conversion (daemon_ha_userspace_convert.go:357
   + protocol_ha.go:57); DNAT composition is internally consistent
   (`merge()` preserves destination rewrites, nat/mod.rs:125, and the SNAT
   allocation uses the effective post-DNAT destination,
   poll_descriptor/mod.rs:2201); tunnel-local entries carry
   `NatDecision::default()` (tunnel.rs:565) — no counterexample.

Trade-offs: closes the security hole AND the availability hole; wire change
only for wire-ambiguous flows; (b)'s squatting DoS avoided. Cost: registry +
holder model + §5.7 foreclosure + §5.8 counters.

### Option (b) — reserve-and-reject: fail the later collider closed

Identical machinery minus the PAT probe: identity-mint Err →
`Unavailable(AllocatorExhausted)`. Smallest diff (strict subset of (a)).
Costs: (i) availability loss Junos does not have (same-id ICMP ping pair
hard-fails the second host); (ii) **identity-squatting DoS** (learned or
brute-forced (port, server) squats deny the victim indefinitely) — converting
a confidentiality bug into an availability bug under the SAME attacker
preconditions. (AGY r1 argued (b); AGY r2+ and Codex r2+ endorse (a).)

### Option (c) — status quo + documentation

Keep the collision; document it. Zero diff; keeps a High-severity silent
misdelivery + hijack/squat primitive on a security-labeled issue.
Recommended AGAINST.

**Recommendation: option (a)** — preserve-first identity reservation + exact
chunked PAT probe + port-less fail-closed token + §5.7 foreclosure with
drain. All three reviewers have endorsed (a) since round 2.

## 5. Concrete design

### 5.1 Registry type and placement

```rust
/// Node-lifetime interface-mode SNAT identity registry, coordinator-owned
/// next to the shared session maps (SessionManager,
/// coordinator/session_manager.rs:12), cloned into every worker
/// (worker/launch.rs:130). ONE allocator per egress ADDRESS (never per
/// rule, never per VRF: the reverse lookup namespace is global-by-address —
/// session/key.rs:9, #2387 open).
pub(crate) struct InterfaceNatAllocators {
    map: RwLock<FxHashMap<IpAddr, Arc<PortAllocator>>>, // 1-address each, 1024-65535
    /// §5.7: addresses whose interface mints are quarantined while a
    /// draining pool/NAT64 domain still holds live allocations on them.
    draining: RwLock<FxHashMap<IpAddr, Vec<Arc<PortAllocator>>>>,
}
impl InterfaceNatAllocators {
    /// ONE write-lock entry().or_insert_with() — the stored winner returns.
    fn allocator_for(&self, egress: IpAddr) -> Arc<PortAllocator>;
    /// LOOKUP-ONLY release path: None when no allocator exists — never creates.
    fn allocator_if_present(&self, egress: IpAddr) -> Option<Arc<PortAllocator>>;
    /// Apply-time + opportunistic release-time reclamation (absent AND
    /// empty); cap 256 RETAINED allocators.
    fn reclaim_absent(&self, live_egress: &FastSet<IpAddr>);
    /// Teardown: drop ALL Worker markers registry-wide (workers joined,
    /// tables destroyed); records emptied -> freed (§5.6).
    fn release_all_worker_markers(&self);
}
```

### 5.2 Admission mint

`match_source_nat_result_for_tuple` gains `iface_allocs: &InterfaceNatAllocators`,
threaded through `match_source_nat_for_flow_result_at`
(afxdp/forwarding/nat.rs:104), `source_nat_decision_for_flow`
(poll_descriptor/nat_exception.rs:24), the #6122 probe
(nat_exception.rs:96), and the coordinator test helper
(coordinator/status.rs:556). The #1377 "exactly two fail-closed decision
sites" textual guard counts decision SITES, not signatures — unchanged.
The interface branch:

```rust
if rule.interface_mode {
    let Some(rewrite_src) = (egress addr of the packet's family) else {
        return Unavailable(InterfaceNoEgressAddress);        // #5688, unchanged
    };
    if non_first_fragment || tuple_unknown {
        return Matched(address-only decision);   // BOTH probe classes: mint nothing
    }
    // §5.7 drain quarantine: fail closed while a draining domain holds live
    // allocations on this address (new-mint gate ONLY — reserves exempt).
    if iface_allocs.is_draining(rewrite_src) {
        return Unavailable(for_rule(rule, SourceNatFailureReason::InterfaceOverlapDraining));
    }
    let alloc = iface_allocs.allocator_for(rewrite_src);     // atomic or_insert_with
    if port_less {
        return match alloc.reserve_address_only(flow, rewrite_src) {
            Ok(_)  => Matched(address-only decision),
            Err(r) => Unavailable(for_rule(rule, r)),
        };
    }
    match alloc.allocate_interface_identity(flow, rewrite_src, now_ns) { /* §4.3 */ }
}
```

### 5.3 Reserve / release scan semantics (tri-state + provenance + drain + tuple-versioned records)

Every reserve and release scan over the occupancy domains becomes
TRI-STATE per domain (Codex r4 blocker 1 — "not this domain" and "identity
conflict" must never be conflated):

```
enum DomainReserve { NotThisDomain, Owned, IdentityConflict }
```

- A domain answers `NotThisDomain` when the translated address is not its
  own (pool does not contain E; interface registry has no allocator for E —
  noting the registry is lookup-only here).
- A domain that owns the address attempts the reserve: success → `Owned`;
  the identity is held by a DIFFERENT flow → `IdentityConflict`.
- Scan order pools (active rules) → draining pools → interface registry;
  the scan STOPS at `Owned` and ABORTS at `IdentityConflict` (the import/
  reserve fails closed — never falls through to a second domain, so no
  cross-domain duplicate is possible even mid-drain: Codex r4's
  counterexample — draining pool owns T, interface reserve of the same T
  falls through — dies here: the draining pool answers IdentityConflict and
  the reserve aborts).
- `nat.nat64` decisions BYPASS the source/interface scan entirely (their
  reserve belongs to `reserve_synced_nat64_allocation`,
  upsert_synced.rs:105) — no double-domain token. (Post-#5144 a NAT64 pool
  is never also a source pool, so this is defense-in-depth, not a behavior
  change.)
- The DRAINING vec participates in BOTH the release and reserve scans
  (AGY r4 major 2: a pool edited/removed while draining leaves its
  allocator out of active `rules`; expiring pool flows' releases and
  mirrored reserves must still reach it — flow-keyed discrimination makes
  double-release impossible: a flow's allocation lives in exactly one
  allocator per tuple).
- **Tuple-versioned ownership records** (Codex r5 blocker 1 — one
  `live_by_flow[flow]` record CANNOT represent the staged-replacement
  overlap where T_old and T_new must both be held; allocator.rs:480 keys
  records by `SourceNatFlowKey` alone, and `reserve_flow`'s stale-drop at
  allocator.rs:1671 unconditionally removes+frees the old record). The
  interface registry's allocators key ownership records by
  `(SourceNatFlowKey, TranslatedTuple)`:
  - idempotent re-entry = a hit on the SAME `(flow, translated)` pair
    (unchanged semantics);
  - a flow MAY transiently hold two records (T_old + T_new) during a
    staged replacement — each with its own holder set;
  - release/rollback match `(flow, translated)` exactly (the construction
    already carries both);
  - **the reserve NEVER auto-drops a different-tuple record** (Codex r6
    major 2: `reserve_flow`'s unconditional stale-drop at
    allocator.rs:1671 is NOT inherited — the §5.6 staged protocol drives
    every marker move explicitly at its own steps; a reserve only ever
    inserts/idempotent-hits the `(flow, translated)` record it was asked
    for);
  - **secondary flow index + selection rule** (Codex r6 major 2: the
    admission mint calls the allocator with only `flow` — the translated
    tuple is what is being decided — so a `(flow, translated)`-only map
    removes the idempotent lookup). A `flow -> SmallVec<records>`
    secondary index backs the mint path. Selection rule: a LOCAL mint
    re-entry returns the flow's locally-minted record (in practice at
    most one exists — a local admission is a single decision episode;
    the two-record transient exists only across a RE-SYNC boundary on the
    standby, where no local mint of that flow runs); reserves present
    their tuple explicitly and hit the `(flow, translated)` record
    directly;
  - `max_tracked_flows` counts RECORDS (a mid-overlap flow counts 2 — a
    bounded transient);
  - the per-index drain counter increments per record's authoritative
    `addr_index`.
  Pool allocators are NOT re-keyed: pool records keep today's
  flow-keyed shape and today's free-on-release semantics (pool holder
  tracking remains #6522's own issue). The tuple-versioned shape is a
  property of the allocator instances the interface registry creates.
- `addr_index` becomes AUTHORITATIVE in every address-only mint/reserve
  path (Codex r4 blocker 3: `reserve_address_only` and its roundrobin
  variant currently write `addr_index: 0`, allocator.rs:1770/1874/1809, so
  the per-index drain counter would misattribute an address-only flow on E
  to index 0 = a different address). The mint/reserve paths record the
  chosen address's real index; stale-tuple moves update it. The drain
  probe is then O(1) per-index live count.
- The nine release sites thread the worker's stable `worker_id: u32`
  (`BindingWorker.worker_id`, worker/mod.rs:108-112).

### 5.4 HA / mixed-version

Synced decisions carry `rewrite_src_port` over the existing wire — no wire
change. Mixed-version rolling upgrade:
- new active → old standby: the old standby IMPORTS the PAT'd decision fine
  (generic field — protocol_ha.go:57, daemon_ha_userspace_convert.go:357;
  AGY r1's "mis-parse" claim withdrawn in AGY r2). The old standby never
  RESERVES it (its reserve skips non-pool rules, nat/source.rs:921).
  Post-failover it can admit a no-PAT flow onto the synced tuple —
  collision probability equal to the pre-existing bug's, not worse.
- old active → new standby: the pair the old active admitted collides on
  the standby exactly as on the active; the new standby pre-reserves the
  first and DROPS the second import on conflict (§5.6); post-failover the
  dropped flow re-establishes. Pinned bulk-sync/failover test (§9).
- Verdict: an ACCEPTED, documented rolling-upgrade window bounded by the
  pre-existing bug's probability, closing when both nodes upgrade.
  `SessionSyncProtocol` gating (pkg/upgrade/imageversions.go:162) rejected.

### 5.5 Fragments / ICMP

First fragment carries L4 → normal admission; the forward fragment assoc
(#2562/#5146) stores the decision (with any PAT port) and non-first
fragments consult it; out-of-order non-first-first fragments drop fail-closed
via the #6122 probe; ICMP echo id collision → second id translated through
the #4074 machinery (RFC 5508 §3.1) including incremental checksum.

### 5.6 Holder ownership and transactional reserve (the lifecycle-complete model)

The holder set on each flow's `live_by_flow` record is a PER-SCOPE
COUNTING structure, not a bare set (Codex r7 blocker 2 — two
holder-bearing rows for one flow can coexist in the same scope: a
fabric base+alias pair in the LEGACY window (the new negotiated-
omission path carries no aliases, but the legacy window keeps them —
§5.6), and a locally-installed entry plus its shared-map row across
scopes; a
`FxHashSet<HolderId>` cannot count two rows in one scope, and deleting
either row must not remove the sole marker while its companion remains
reachable):

```rust
struct HolderSet {
    /// worker_id -> count of holder-bearing rows for this record in that
    /// worker's table (locally installed entry + materialized replica +
    /// legacy-window alias entry each count one).
    per_worker: FxHashMap<u32, u16>,
    /// count of holder-bearing rows in the shared canonical map
    /// (base canonical row + legacy-window explicit fabric alias row).
    shared_rows: u16,
}
```

Reverse companions and derived reverse/forward-wire INDEX rows are
holder-neutral. Every acquire adds one unit at its scope; every release
removes one unit at its own scope (per-holder-owner discipline); the
record's identity frees only when `per_worker` is empty AND
`shared_rows == 0`. Saturating-decrement clamp + flow+tuple-keyed release
(a stray decrement can never touch a different flow's allocation).

- **Local admission**: mint inserts `{Worker(W)}` at decision time —
  RESERVE-BEFORE-INSTALL by construction (install-refused aborts roll back
  via the existing rollback sites).
- **Local publication acquires {Shared}** (Codex r4 blocker 5):
  `publish_shared_session` gains the registry parameter and, for FORWARD
  entries whose decision's `rewrite_src` resolves to an interface-registry
  allocator (`allocator_if_present`) with a live record for this flow,
  inserts `{Shared}` into that record (idempotent — the canonical insert
  below). Without this, worker expiry released the only holder
  (loop_body/mod.rs:1625) before the Close-delta removed the shared row
  (session_delta.rs:436) — the early-free shape the holder model exists to
  eliminate. Reverse companions are holder-neutral.
  `remove_shared_session` gains the registry parameter and removes
  `{Shared}` (the canonical row's removal at
  session_delta.rs:436/446, promote.rs:181, session_glue/mod.rs:587/938/945,
  session_import.rs:314/329, local_delivery.rs:91 — the closed inventory,
  SMR r3 M13 including the note that a locally-owned reap reaches removal
  VIA THE CLOSE-DELTA RELAY, not at reap time).
- **Sync import — TRANSACTIONAL at the coordinator**: the coordinator
  pre-reserves the identity (+`{Shared}`) BEFORE `publish_shared_session`
  (ha/session_import.rs:131-137 publishes before fanning worker upserts at
  :233). On identity CONFLICT the import is DROPPED (counted by
  `xpf_userspace_interface_snat_sync_identity_conflict_drops_total` + one
  Debug line) — fail-closed: the standby never holds a session it cannot
  own. Pre-reserve gates `is_reverse`. Bulk-sync replay is idempotent. The
  HA-fidelity DoS (an attacker on the standby's segments squatting a synced
  identity so every refresh import loses) is EXPLICITLY ACCEPTED and
  EXPOSED (Codex r3 major 6: drop is the safer posture;
  quarantine-with-retry adjudicated and rejected — a quarantined session
  still cannot forward at failover but holds table state).
- **Worker-side sync install — RESERVE-BEFORE-INSTALL**: the single
  `install_synced_with_reserve(...)` wrapper = (1) reserve/+`{Worker(W)}`
  (idempotent-hits the coordinator's pre-reserved record); on reserve
  FAILURE → do NOT install (drop the command, count, Debug); (2) install;
  on install refusal → release the just-added holder (rollback). Used by
  ALL THREE sync-family install sites (AGY r3 verified the inventory
  complete): `WorkerCommand::UpsertSynced` (commands/upsert_synced.rs:65),
  `materialize_shared_session_hit` (session_glue/mod.rs:1130),
  `WorkerCommand::UpsertLocal` (session_glue/mod.rs:808).
  **Materialize failure semantics** (Codex r4 major 7 + r5 major 4):
  materialize is not a command, and a `None` lookup return does NOT drop
  the packet — `resolve_flow_session_decision` returning None at
  session_glue/mod.rs:1227 makes the caller treat it as an ORDINARY
  session miss and enter the full cold policy/NAT/admission path
  (poll_descriptor/mod.rs:432/903). The wrapper's reserve-conflict
  therefore returns a DISTINCT `MaterializeConflict` outcome propagated to
  an explicit recycle/drop branch (packet recycles, counted) — never the
  cold-admission path and never the unconditional shared decision
  (session_glue/mod.rs:1128/1146 today).
  **Dropped-command gap** (AGY r4 adjudication): a worker whose
  `UpsertSynced` dropped never installs the entry; failover onto that
  worker takes the standard no-session re-establishment path — no
  confidentiality compromise; a later genuine refresh re-publishes and
  re-queues. The coordinator's `{Shared}` for such an entry persists by
  design ({Shared} rides the canonical row, removed by the peer's
  delete-sync or entry expiry — AGY r4 minor 3, documented accepted
  asymmetry, not fed back).
- **Tuple-changing re-sync — STAGED REPLACEMENT protocol on
  tuple-versioned records** (Codex r4 blocker 6 + r5 blockers 1-2):
  - Coordinator: pre-read the canonical row's CURRENT tuple T_old →
    pre-reserve T_new (+`{Shared}` on the NEW `(flow, T_new)` record —
    the tuple-versioned record shape of §5.3 lets T_old and T_new coexist)
    → canonical insert displacing T_old's row → ALIAS SWEEP: remove every
    reverse-index/forward-wire alias derived from the DISPLACED entry
    (reverse_wire/reverse_canonical/forward_wire of T_old — today's
    `publish_shared_session` only inserts the new aliases at
    shared_ops.rs:918-943 and never removes the old tuple's, so a stale
    alias would stay resolvable; this sweep is new and also fixes the
    pre-existing stale-alias residual for any tuple-changing republish.
    The sweep mirrors `remove_shared_session`'s exact conditionals
    (reverse_canonical removed only when `!= reverse_wire`; forward_wire
    only when `!= key`) and is FILTERED against the new entry's aliases —
    a same-tuple refresh (T_old == T_new) sweeps nothing, so the entry
    never loses aliases it still needs (SMR r6 nit 1). The sweep is
    COMPARE-AND-REMOVE ownership-validated (Codex r7 major 4 + r8 major 2
    + r9 major 2 — the current removals delete derived slots by key
    unconditionally, shared_ops.rs:978/987/997, so a third-party
    non-bijective occupant of T_old's slot would be swept; and "key +
    NatDecision" is not a sufficient identity, since a newer
    same-key/same-NAT session can carry a different stable identity, and
    the swept maps store `SyncedSessionEntry`, whose only id field is the
    cross-node RT-flow id (worker/mod.rs:375) — the Go node-local
    SessionID is never transmitted (manager_ha.go:1645) and LOCAL
    publications store `session_id: 0` (poll_descriptor/mod.rs:2569)).
    The ownership identity therefore uses a HELPER-LOCAL publication
    token: `SyncedSessionEntry` gains an additive `pub_token: u64` — a
    coordinator-local monotonic counter stamped at publish into BOTH the
    canonical row and every derived index row of one publication
    (helper-internal struct change, NOT a wire/Go change). Every swept
    removal validates ownership ATOMICALLY under the removing map's own
    lock (the maps lock separately — a third party can replace a derived
    slot between canonical replacement and sweep, so check-then-remove
    across locks is insufficient) against the identity chain: equal
    non-zero `RTFlowSessionID`, else equal non-zero `pub_token`, else
    (token-0 legacy rows only) full `SyncedSessionEntry` equality
    excluding counters — two token-0 rows that agree on every remaining
    field are semantically the same session for routing purposes (AGY r9's
    field enumeration), so removing either is indistinguishable. A
    third-party-displacement test, a same-key/same-NAT/different-id
    replacement test, and a newer-local-publication (session_id 0,
    non-zero pub_token) test pin it — Codex r11 major 3's restore)
    ) → `−{Shared}` on T_old. T_old stays held by its `{Worker}` markers
    (never freed mid-overlap); its canonical row and aliases are already
    unreachable when the marker drops.
  - Worker wrapper: pre-read the existing entry's tuple T_old via a NEW
    read accessor (Codex r5 blocker 1: `entry_by_key` is private,
    session/mod.rs:1093 — add a narrow `translated_tuple_of(key)` accessor;
    `upsert_synced_with_origin` keeps its bool return, AGY r5 nit 2's
    `Option<NatDecision>` return is the optional alternative) → reserve
    T_new (+`{Worker(W)}`) → install (in-table replace makes T_old
    unreachable, session/install.rs:322) → release T_old (`−{Worker(W)}`).
    T_old's record empties → freed, only AFTER it is unreachable on every
    scope that referenced it.
  - Each side decrements only its own marker (SMR r3 M14); cross-site
    windows are bounded by the fanout and are hold-safe direction
    (never free-early).
- **Worker-thread teardown — marker drop** (Codex r4 blocker 4 + AGY r4
  major 1): `stop_and_clear` (worker_manager.rs:141) joins worker threads,
  whose tables drop WITHOUT release routines (worker exit only flushes
  counters + CoS leases, loop_body/mod.rs:1563). After the join,
  `release_all_worker_markers()` drops every `{Worker(*)}` registry-wide;
  records emptied → freed. Path matrix (Codex r4's inventory):
  - `stop_inner(false)` — full reconcile (teardown.rs:80) and bind-
    incomplete rollback (bringup.rs:213): worker tables DESTROYED; canonical
    shared entries SNAPSHOT-PRESERVED (teardown.rs:56) and REPLAYED
    (coordinator/mod.rs:810). Worker markers dropped at join; `{Shared}`
    survives (canonical rows persist); replay re-acquires `{Worker}` via
    the wrapper on the new workers.
  - `stop_inner(true)` — link-cycle stop (coordinator/mod.rs:459) and
    process exit (:471): workers joined (worker markers dropped) AND the
    shared maps cleared wholesale — the clear FIRST iterate-and-releases
    `{Shared}` per forward interface-mode entry (AGY r3 major 2), then
    clears; with both marker classes gone the registry holds nothing for
    the wiped state.
  - Same-plan refresh: worker tables PERSIST — no marker event at all.
- **Fabric forward-wire alias: negotiated sender omission (new+new) +
  receiver-side signature quarantine (legacy window) — Codex r6-r13
  converged design**: HA session sync deliberately exports a
  fabric-redirect session TWICE — the canonical forward key AND a derived
  NAT-translated forward-WIRE alias key
  (`userspaceForwardWireAliasFromDeltaV4`,
  daemon_ha_userspace_stream.go:370/373). Rounds 6-10 established the
  alias cannot live in the ownership model; r11-12 established no
  existing field can carry an exact marker (the cluster codec truncates
  `Flags` to one byte, sync_protocol.go:116/122/231/237); r13 established
  a key-only receiver heuristic cannot disambiguate deletes (a genuine
  direct row and an alias can share one key, and deletes carry only the
  key + a fresh per-key generation, sync_protocol.go:326,
  sync_conn_gen.go:156/263). Codex r13's own direction — "exact delete
  provenance — or negotiated sender-side alias omission" — is adopted:
  - **New+new path: negotiated sender-side alias omission.** The
    receiver advertises an additive "omit forward-wire aliases"
    capability (old peers ignore it — sync continues with legacy
    behavior). The channel must work on UNAUTHENTICATED clusters too
    (AGY r14 minor 1: `performSyncHandshake`, sync_auth.go:331-334, is
    bypassed when no auth key is configured — `handleNewConnection`,
    sync_conn.go:100-137, opens the stream with no setup handshake —
    so the capability rides ONE named contract: an additive periodic
    `syncMsgCapability` frame on a dedicated ticker (period chosen at
    implementation, e.g. the clock-sync cadence — SMR r18 nit 2;
    Codex r17 minor 2:
    the transport must be one contract, not alternatives — and NOT a
    handshake field, because unkeyed deployments bypass the handshake,
    sync_auth.go:321) — RE-ADVERTISED PERIODICALLY (Codex r16 minor 3:
    `sendClockSync` currently runs only ONCE at connection setup,
    sync_conn.go:137, so the re-advertisement needs a named transport:
    a new periodic capability ticker, or piggybacking on an existing
    periodic session-stream message — the implementer picks one and the
    per-peer capability state RESETS TO UNKNOWN on every (re)connection)
    — so a lost frame self-heals within one period (Codex r15 minor 2: a
    one-shot frame has no defined UNKNOWN → unsupported transition;
    periodic re-advertisement gives every connection a bounded path to
    capability discovery with no handshake dependency — the
    unauthenticated-cluster case is covered, sync_auth.go:321 bypass).
    The sender's rule is DERIVE-UNTIL-CAPABLE: peers start UNKNOWN and
    the sender keeps deriving (today's exact behavior) until a
    capability frame arrives, then omits from that point on. No
    emission hold is needed: a mid-stream transition only means some
    early aliases flowed, and those are exactly what the receiver-side
    quarantine (below) exists to confirm and drop — the transition is
    safe by construction, and a permanently lost capability simply
    stays legacy (never drops sync). A sender that has learned the
    capability SKIPS the alias derivation entirely at ALL FOUR alias
    branches — V4/V6 open AND V4/V6 close
    (daemon_ha_userspace_stream.go:370/379 upserts, :398/:413 deletes;
    Codex r16 minor 3: the omission gate must cover alias deletes too)
    — zero alias upserts, zero alias deletes on the wire. Nothing is dropped at the receiver, no
    signature is needed, NO collateral exists: genuine self-NAT and
    identity-NPTv6 rows flow normally. The alias's work is done by the
    derived forward-wire index row the base session's own publish
    inserts (shared_ops.rs:943-957) — verified five times independently
    (AGY r9/r11/r12/r13, Codex r9/r10/r11/r12/r13) as serving every
    fabric-return lookup the explicit alias row served. The broken
    synthesized-companion hazard (un-NAT replies to the firewall's own
    address every sweep, shared_ops.rs:750 + nat/mod.rs:106 — a live
    shipped bug) closes wherever the sender omits, with zero receiver
    machinery.
  - **Legacy window (peer does not advertise): receiver-side signature
    QUARANTINE, not blind drop.** The old sender keeps emitting
    canonical+alias rows; the new receiver quarantines suspected-alias
    upserts instead of importing or blind-dropping them:
    - **Signature** (computable at the pkg/cluster decode boundary,
      before bulkRecv bookkeeping, sync_conn_read.go:110):
      forward ∧ sync-derived ∧ SNAT flag set ∧ NOT NAT64 (decoded
      `Nat64SnatV4` present, sync_protocol.go:616 — Codex r13 blocker 2:
      a v4 NAT64 rewrite is padded into a v6 slot and reformatted as an
      IPv6 address, eventstream.go:1350, so a legitimate NAT64 client at
      that address WOULD match the source-only signature — the NAT64
      exclusion is mandatory) ∧ `key.src_ip == decision.rewrite_src` ∧
      (`key.src_port == decision.rewrite_src_port` OR
      `rewrite_src_port == 0`) — full rewritten-tuple equality (Codex
      r13 major 3a: same-address pool/interface PAT and same-IP static
      mapped-port sessions are bijective by port and must NOT match;
      static NAT rewrites address AND mapped port, static_nat.rs:746).
      NO disposition/FabricRedirect gate (Codex r14 blocker 1:
      `userspaceSessionFromDeltaV4/V6` does NOT copy FabricRedirect into
      `SessionValue` — only SNAT/DNAT and FabricIngress survive,
      daemon_ha_userspace_convert.go:357/462 — so the cluster codec
      carries no disposition field at all, sync_protocol.go:114/229, and
      the legacy sender cannot provide one. The priced consequence:
      NON-fabric identity-NPTv6 canonical rows also quarantine and
      timeout-admit — a bounded 5s sync delay for a corner-of-corner,
      not a drop).
    - **Quarantine**: a bounded per-peer map (4096 entries, tunable)
      holding signature-matching upserts, PINNED TO ITS ARRIVAL BULK
      EPOCH. **Overflow is a terminal bulk abort, never an eviction**
      (Codex r16 blocker 1: bulk bookkeeping retains only KEYS
      (sync_conn_read.go:200) and the decoded value is consumed
      immediately, so an evicted frame cannot be admitted later — its
      payload is gone; and blind drop could lose genuine self-NAT /
      identity-NPTv6 rows). On overflow the receiver ABORTS the
      incomplete bulk WITHOUT ACK (no reconcile, no sync-hold release),
      counts the saturation
      (`xpf_userspace_session_sync_alias_quarantine_overflow_total`,
      Go-side), applies a per-peer re-prime backoff, and lets the
      sender's bulk machinery retry — the retry re-drives every row,
      so nothing is lost permanently; a persistently overflowing
      deployment (>4096 fabric SNAT sessions in one bulk) must raise
      the cap, and the saturation counter makes the pressure visible.
      The abort CYCLE cost is priced honestly (Codex r18 minor 3): each
      successful full-disconnect ALSO fires the peer-disconnect/connect
      lifecycle callbacks (sync_conn.go:569/142) — config
      reconciliation plus DHCP and IPsec re-advertisement
      (daemon_ha_sync.go:934) — so a persistently overflowing
      deployment pays REPEATED CLUSTER-WIDE SYNCHRONIZATION CHURN per
      cycle, not merely one cold re-prime; the cap is therefore sized
      at provisioning so genuine fabric-session counts never saturate
      it in steady state (the 4096 default assumes ≤~4k fabric SNAT
      sessions per bulk; larger deployments raise it up front), and the
      overflow counter + backoff are the visible escape hatch for the
      undersized case, not the steady-state plan.
      **The abort recovery contract is a GENERATION-FENCED, ATOMIC
      CLUSTER-LEVEL TEARDOWN with commit-time generation validation**
      (Codex r17 blocker 1: no retry mechanism exists today —
      `BulkSync()` is write-only (sync_bulk.go:169/183/195), connection
      setup clears needColdPrime before any ACK (sync_conn.go:194), a
      missing ACK merely stays in pendingBulkAckEpoch with no
      ACK-timeout retry (sync_conn_read.go:257), and the survivor
      re-drive's `outboundBulkAcked` flag is intentionally sticky
      (sync.go:479). Codex r18 blocker 1: two `Close()` calls do NOT
      guarantee the full-disconnect transition — receive loops remove
      connections independently via deferred callbacks
      (sync_conn_read.go:14), `handleDisconnect` runs full cleanup only
      if both slots happen to be nil at that instant
      (sync_conn.go:483/496), and a reconnect installed between the two
      old disconnect callbacks sees a NONEMPTY registry, so neither a
      full-disconnect edge nor needColdPrime is armed
      (sync_conn.go:244/278). Codex r19 blocker 1: a fence stated only
      at `installConn` is still insufficient — receive handlers
      dispatch frames WITHOUT checking registry membership or
      generation (sync_conn_read.go:91) and those frames can install
      sessions (:109) or replace bulk state (:183), so a handler can
      pass a pre-dispatch check, stall, and mutate state AFTER the
      reset; and a legacy peer's PENDING FIRST FRAME is processed
      BEFORE `installConn` (sync_conn.go:119/130), so an install-gate
      alone cannot stop an old peer from mutating receiver state during
      the fence; and `installConn`'s current result cannot express
      refusal while `handleNewConnection` unconditionally starts the
      receive loop afterward (sync_conn.go:130)). The transition
      contract is therefore:
      (1) **Fence state**: an atomic ABORT-GENERATION counter + fenced
      flag in the connection registry. On any abort (overflow,
      deadline, teardown) the receiver increments the generation and
      sets the fence — one atomic store on the serialized event loop.
      (2) **Admission verdicts**: `installConn` returns
      ADMITTED/REFUSED (its result type gains the verdict; today it
      cannot express refusal). A REFUSED connection is closed
      immediately with NO pending-frame processing, NO receive-loop
      launch, NO clock sync, NO lifecycle callbacks, and NO cold-prime
      work (Codex r19: `handleNewConnection` must become conditional on
      the verdict, sync_conn.go:130).
      (3) **Install-before-dispatch**: a connection's pending first
      frame is dispatched ONLY AFTER an ADMITTED installation
      (reordering sync_conn.go:119 → :130), and it carries the same
      generation guard as (4) — so an old peer's pending frame can
      never mutate receiver state during a fence (Codex r19's
      old-peer bypass).
      (4) **COMMIT-TIME generation validation**: every stateful frame
      application on the serialized receiver loop (session install,
      bulk-state mutation, quarantine action) re-checks the frame's
      generation against the current abort generation AT THE COMMIT
      POINT — a frame carrying an older generation, or any frame
      arriving while the fence is set, is discarded at commit (Codex
      r19's pass-check-then-stall race: a handler that passed a
      pre-dispatch check and then stalled can never mutate
      post-reset state, because the commit-time guard re-validates at
      the mutation point, not at handler start).
      (5) **Reset-once ownership**: when both slots confirm detached
      (or the named AbortFenceTimeout fires — a wedged handler's frames
      are commit-discarded per (4), so the reset is safe on timeout),
      the bulk / quarantine / capability STATE RESET runs EXACTLY ONCE,
      inside the serialized loop, owned by the fence transition — never
      per-callback. A second abort raised inside an active fence is a
      no-op when it carries no newer abort generation, or re-arms the
      fence at the higher generation with the same reset-once
      semantics.
      (6) **Peer convergence**: the fence clears and the
      abort-triggered per-peer backoff applies (unrelated disconnects
      are never delayed). The peer's reconnect attempts during the
      fence are REFUSED at (2); it retries and lands after cleanup on
      the genuine empty→connected cold-prime edge (sync_conn.go:139/
      :551, sync_bulk.go:65) with a FRESH bulk and a FRESH epoch —
      and the peer needs no fence awareness: the receiver-local fence
      enforces the transition regardless of peer version. Inbound
      frames from the aborted epoch are discarded by the TCP teardown
      (the discard-until-end alternative is rejected: session handlers
      use `bulkInProgress` only for bookkeeping and install trailing
      frames normally, sync_conn_read.go:109). This also covers the
      fourth epoch-death shape Codex named (single active-fabric reset
      after a prior successful bulk while the other fabric survives).
      Entries pinned to an aborted epoch are dropped fail-closed with
      the connection state (see the epoch-death rule below).
      §9 pins the race tests: install-between-detachments refused at
      (2); pending-frame-before-install discarded at (3); a stalled
      handler's post-reset frame discarded at (4); wedged-handler
      AbortFenceTimeout reset at (5); nested abort re-arm at (5)
      (Codex r15 blocker 1 — deferred cross-epoch admission is unsafe:
      a frame quarantined in bulk E1 and admitted at wall-clock timeout
      would (a) race E1's BulkEnd reconcile, which deletes sessions
      absent from E1's received set — see the bookkeeping rule below —
      while the receiver ACKs the bulk and releases the sync-hold with
      the row still missing (sync_conn_read.go:240/244), and (b) be
      counted as part of a LATER bulk E2 if E2 starts first, falsely
      retaining a stale row whose delete was lost. Resolution is
      therefore EPOCH-DEFINITIVE: all quarantine actions run as events
      on the receiver's SERIALIZED event loop (a timer only enqueues a
      wakeup — the import path's generation-check/install/record
      sequence is safe only single-threaded, sync_conn_gen.go:381),
      and every quarantined entry RESOLVES AT THE EARLIEST OF:
      (i) ITS OWN BULK'S BulkEnd — at BulkEnd the complete snapshot is
      present, so the sibling-base check is definitive for that epoch —
      still-matching entries whose sibling base is in the received set
      CONFIRM-alias and drop; everything else is ADMITTED through the
      complete normal import path in the same serialized pass, BEFORE
      the bulk is ACKed and the sync-hold released;
      (ii) A SUPERSEDING BulkStart (Codex r16 blocker 2: fabric 0 can
      drop mid-E1 while fabric 1 survives — receiver bulk state resets
      only when ALL fabrics are down, sync_conn.go:496/554, the sender
      can re-drive a new bulk on the survivor, and E2's BulkStart
      UNCONDITIONALLY OVERWRITES E1's epoch and received maps,
      sync_conn_read.go:183/198 — so E1's pinned quarantines never
      receive their own BulkEnd). At a superseding BulkStart the PRIOR
      epoch's pinned entries are DROPPED fail-closed BEFORE the maps
      are overwritten — no cross-epoch leakage, and the superseding
      bulk re-sends every row anyway, so genuine rows re-quarantine and
      resolve on the completed retry (bounded delay, never a poison);
      (iii) A BULK DEADLINE / TEARDOWN (Codex r16 blocker 2: no receive
      deadline exists today — read timeouts merely send heartbeats,
      sync_conn_read.go:27, and the 30s VRRP timeout releases sync hold
      degraded without tearing down the bulk, manager.go:372 — so a
      per-bulk RECEIVE DEADLINE is required new behavior: on deadline
      the incomplete bulk aborts WITHOUT ACK, per the overflow-abort
      rule, and its pinned entries drop fail-closed per (ii)).
      Entries received OUTSIDE any bulk
      (incremental deltas) resolve on a 5s fallback timer instead —
      incremental frames carry no reconcile semantics, so the same
      confirm-vs-admit rule applies with the CURRENT store as the
      definitive state. No frame ever defers past its own bulk epoch).
      **Bulk bookkeeping is NOT gated**
      (AGY r15 blocker 1: a quarantined key is STILL RECORDED in
      `s.bulkRecvV4/V6` at decode time — it was genuinely received in
      the bulk — because `reconcileStaleSessions` /
      `ReconcileClusterBulk` (sync.go:1086-1126) treats any live
      session whose key is absent from the received set as stale and
      DELETES it at BulkEnd; gating the bookkeeping would delete every
      genuine self-NAT / identity-NPTv6 session ~50 ms after the bulk
      completes, before any resolution could run. The
      quarantine gates ONLY the import (install / publish / reserve /
      companion synthesis), never the "was received" record).
      Confirmation is ORDER-AGNOSTIC (Codex
      r14 blocker 2: the sender queues canonical base FIRST and alias
      SECOND on open, daemon_ha_userspace_stream.go:370/375/384, so the
      base has normally ALREADY been imported when the alias arrives —
      confirmation checks the CURRENT session store for a sibling
      canonical base at quarantine INSERTION (a canonical row whose
      forward-wire form equals the quarantined key with an identical
      NatDecision and an equal NON-ZERO RTFlowSessionID — the r6-r8
      predicate, reliable for an actual pair) and confirms immediately;
      only when NO sibling base is present (the lossy-reorder
      alias-first case) does the entry wait for the base's arrival or
      the timeout). A confirmed entry is dropped and its key enters the
      delete-suppression set. On timeout the entry is ADMITTED as a
      canonical row by DISPATCHING THE STORED FRAME INTO THE COMPLETE
      NORMAL import path — generation checks, timestamp rebasing,
      coordinator reserve, and helper dispatch
      (`WorkerCommand::UpsertSynced`), identically to a non-quarantined
      frame reaching `installClusterSynced*` (sync_conn_read.go:110 →
      sync_conn_gen.go:435; AGY r14 nit 2 + Codex r14 minor 4) — PLUS a
      guarded bookkeeping touch: the key is added to the CURRENT bulk's
      received set ONLY IF a bulk is currently open (AGY r15 blocker 1:
      after BulkEnd the map is nil'd, sync.go:1090, so an unconditional
      write panics with assignment-to-nil-map; and a session admitted
      between bulks needs no bookkeeping at all — reconcile only runs
      at BulkEnd):
      this is the genuine self-NAT case, the identity-NPTv6
      fabric-redirect case (no alias is ever derived for it —
      daemon_ha_userspace_convert.go:511 returns false when wire == key),
      and the genuinely-lost-base alias case (which degrades to TODAY's
      behavior for that case — bounded, and only on a wire loss).
    - **Deletes**: suppressed only for keys in the
      confirmed-delete-suppression set, with the lifecycle matching the
      actual close ordering (Codex r14 blocker 2: the exporter queues
      the BASE delete BEFORE the alias delete in the same close delta,
      daemon_ha_userspace_stream.go:398/403 — so the suppression entry
      does NOT clear when the base's delete processes; it clears when
      the FIRST delete for the key AFTER the base's delete is consumed
      (the alias's own delete, which the suppression then swallows), or
      on a short bound if that delete was lost on the wire). Documented
      residual: a genuine DIRECT row sharing the key with a confirmed
      alias (the #2387 overlap corner) whose own delete arrives while
      suppression is active is suppressed and the row strands until its
      OWN session timeout (bounded — entries expire on their own
      timeouts) — versus TODAY, where the alias upsert clobbers that
      row at publish with certainty (shared_ops.rs:907). Every matrix
      cell is strictly safer-or-equal to today.
  - **Why dropping/omitting is safe (verified five times)**:
    the explicit alias row is REDUNDANT with the derived forward-wire
    index row the base session's own publish inserts
    (shared_ops.rs:943-957): exact shared lookup falls through to that
    derived index (shared_ops.rs:630); materialization carries the base
    canonical key (shared_ops.rs:549); RG-promote republish indexes the
    derived map (shared_ops.rs:432-437/:950); activation prewarm needs
    only the base rows; BPF publication emits canonical + forward-wire
    + reverse-wire + reverse-canonical keys for the base
    (bpf_map/mod.rs:76). No Rust forwarding consumer requires the
    explicit row.
  - **Side fix (a live shipped hazard, verified by Codex r11/r12 and AGY
    r11)**: the import path synthesizes a reverse companion for every
    forward import including alias rows
    (synthesized_synced_reverse_entry, shared_ops.rs:750 — no alias
    detection), and `NatDecision::reverse` sets `rewrite_dst` to the
    supplied original source (nat/mod.rs:106), so an alias entry yields
    a companion that un-NATs replies to the firewall's own address E
    instead of the client H. Base and alias companions derive the SAME
    reverse key K=(S→E) (session/key.rs:94); the alias's companion
    publishes SECOND (canonical-then-alias export order,
    daemon_ha_userspace_stream.go:370) and displaces the correct one in
    the last-write-wins shared reverse map every sweep — the churn the
    `record_shared_nat_displacement` exclusion documents
    (shared_ops.rs:92-120). Return packets consult the exact session key
    K (shared_ops.rs:602/630), so the poisoned companion is
    forwarding-relevant TODAY. Sender omission (new+new) and
    quarantine-confirmation (legacy) both prevent the poisoned
    companion from ever forming; `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS`
    goes quiet for fabric-redirect SNAT sessions.
  - **Mixed-version matrix** (no cell regresses): new+new: omission —
    zero alias traffic, zero collateral. old sender + new receiver:
    signature quarantine — genuine rows admitted after the window (a
    sync DELAY, not a drop, for the corner), aliases confirmed-dropped;
    better than today (no broken companion), priced as documented
    residual. new sender + old receiver: no advertisement → sender
    keeps deriving; old receiver treats aliases as canonical — TODAY'S
    exact behavior (broken companion included — the status quo, not
    worse). old + old: status quo.
  - **Helper side**: NO alias-specific handling at all — the ownership
    machinery (reserve/holders/tri-state/staged replacement) sees only
    canonical rows.
- **Neutral paths**: promote (promote.rs:99), demote (install.rs:568),
  #1752 in-place refresh — NO reserve/release calls.
- **Reverse-companion lag (documented inherited window, SMR r5 N16)**:
  forward and reverse companions of one flow can live in DIFFERENT
  workers' tables (internal and external tuples hash differently). The
  identity frees when the holder set empties (forward reap −{Worker} +
  canonical removal −{Shared}), while a reverse companion elsewhere is
  holder-neutral and lingers until its own reap or the delete-replication
  relay (`replicate_session_delete` — it ENQUEUES per-worker commands,
  session_glue/mod.rs:881, so the bound is queue/relay-or-expiry, not a
  strict millisecond deadline; the session_delta.rs:436-446 removal
  covers both keys) reaches it — a queue/relay-or-expiry-bounded window
  in which a re-minted identity's reply could land on the lingering
  reverse entry. This window exists TODAY for pool mode (pool port freed
  at forward reap while the reverse companion lingers; the #3011 recycle
  FIFO is only a reuse-delay, also churnable), so the change does not
  widen it; closing it belongs to the session-teardown domain, not this
  NAT-admission fix. The core invariant statement is scoped accordingly:
  continuous holding on every scope EXCEPT the relay-bounded
  reverse-companion edge, which matches shipped pool discipline.
- Net effect: the identity survives while ANY HOLDER-BEARING FORWARD
  replica or shared canonical row lives node-wide (reverse companions are
  holder-neutral by design — Codex r6 nit 5) — the #6522 hazard cannot
  exist in this registry.

### 5.7 Cross-domain overlap foreclosure with DRAIN (Codex r3 blockers 1-2, r4 blockers 2-3)

The interface registry, source-pool allocators, and NAT64 allocators are
DISJOINT occupancy domains; a source pool (or NAT64 pool) containing an
egress interface address reintroduces the collision across the seam.
Foreclosure at BOTH layers, plus a DRAIN discipline for already-live
sessions:

1. **Commit validator** (#5144 extension): interface-mode egress addresses
   join the owner set DEDUPED BY ADDRESS (multi-rule same-WAN configs must
   not false-reject). Overlap → REJECT at strict commit; WARN on tolerant
   load / peer-sync (#5837/#1960 no-brick doctrine).
2. **Snapshot builder + DRAIN** (interface snapshots resolve LIVE kernel
   addresses, interfaces.go:455-465; DHCP triggers a full recompile on
   address change, daemon_dhcp.go:73/85):
   - **Egress-address derivation matrix** (Codex r4 major 8): per
     interface-mode rule, the overlap candidate set is — `to-interface`:
     that interface's addresses; `to-zone`: the zone's interfaces'
     addresses; `to-routing-instance`: the RI's interfaces' addresses;
     NO to-side scope (or from-side only): ALL dataplane interfaces'
     addresses (wildcard, matching the Rust `scope_matches` semantics at
     nat/source.rs:351 — the Go precedent that collected only non-empty
     `ToZone` and returned nothing for unscoped rules, maps_sync.go:1735,
     is insufficient and is replaced). §9's builder test matrix covers all
     four scope shapes.
   - Any pool address overlapping a derived candidate address marks that
     POOL unusable (`pool_failure`/`PoolUnusable` — fail-closed NEW pool
     admissions). NAT64: the overlapping rule is emitted with an EMPTY pool
     (shipped native fail-closed at nat64.rs:1123; the old NAT64 allocator
     is retained SEPARATELY from the active empty prefix — normal reuse
     requires a byte-identical pool, nat64.rs:937, Codex r4 verified).
   - The dataplane RETAINS the quarantined pool's previous allocator as a
     DRAINING domain (a compatibility carry-over key that ignores the new
     failure marker and survives repeated quarantined snapshots — Codex r4
     verified the current `allocator_key()` drops carry-over on
     `pool_failure`, source.rs:337/726, so the drain retention is an
     explicit new key); releases and mirrored reserves keep reaching it
     (§5.3 drain-vec scan); the per-index live counter (§5.3's
     authoritative `addr_index`) makes the drain O(1)-observable.
   - **Uniform mint quarantine** (Codex r5 blocker 3 — v5 quarantined
     only INTERFACE mints, so a re-enabled edited pool could mint an
     identity an older draining generation still owns): while ANY
     generation/domain holds live allocations on an address E, NEW mints
     on E are quarantined in EVERY domain — pool admission SKIPS
     quarantined addresses in its address loop (allocates on a
     non-quarantined pool address; exhaustion only if ALL are
     quarantined — and an address-persistent/sticky pool, whose loop is
     single-attempt by contract, yields `AllocatorExhausted` when its
     sticky address is quarantined: fail closed, NEVER rotate a sticky
     flow to a different address — SMR r6 nit 2; the same fail-closed
     posture applies to deterministic CGNAT (fixed address derived from
     the subscriber, allocator.rs:1482), persistent-NAT pinned-address
     reuse — BOTH the address-only persistent path (allocator.rs:1955)
     AND the port-translating persistent path that returns a pinned lease
     BEFORE the address loop (allocator.rs:1114, so the quarantine gate
     sits at the lease decision, not only in the loop — Codex r7 minor
     5), and deterministic NAT64 (allocator.rs:1561)), NAT64 likewise,
     interface-mode mints fail closed
     (`InterfaceOverlapDraining`) since their "pool" is the single
     address. Reserves (ownership claims for existing sessions) are never
     quarantined — they are tri-state per §5.3.
   - **Drain-marker ordering** (Codex r4 blocker 2): the drain marker for
     an address E is installed in the registry BEFORE the new RuntimeView
     is published to workers (before the worker-visible store at
     snapshot_refresh.rs:458/472 — early installation is safe, it can only
     over-quarantine; late installation is not). Under the OLD dataplane
     state the overlap does not yet exist (the pool edit / address
     addition is not applied), so mints before the marker are consistent
     with the old config; mints under the new state are quarantined from
     the first packet. The v4 "race window" is CLOSED, not documented.
   - **Atomic drain lift**: when the drain empties, the draining entry and
     its allocator are removed from the draining map under ONE registry
     lock, and the quarantine lifts in the same critical section — a late
     synced reserve after that point gets `NotThisDomain` from the
     (removed) pool domain and transfers to the interface registry
     (ownership continuity), never resurrects the drained allocator
     (Codex r4 blocker 2's closed/resurrection protocol). A re-ENABLED
     pool (marker removed by a later config) starts minting on its
     non-quarantined addresses immediately and on E only after every
     older generation for E drains (the uniform rule above).

### 5.8 Observability (additive, production)

Four ADDITIVE optional counters on the existing helper status wire,
plumbed via the FULL #1760-W3' precedent (protocol/control.rs:343 +
coordinator/status.rs:241 + server/lifecycle.rs:228 init +
server/helpers/status.rs:102 refresh; protocol_status.go:287 +
pkg/api/metrics.go:377 + Describe registration at metrics.go:791 +
metrics_descriptors_userspace_session.go:27 + metrics_userspace.go:677;
additive per #1961), PLUS THREE GO-side Prometheus counters (the
§5.6 alias-discipline counters — no helper wire involvement):
- `xpf_userspace_interface_snat_pat_collisions_total` — identity-mint
  conflicts that took the PAT probe;
- `xpf_userspace_interface_snat_identity_exhaustion_total` — completed
  full-cycle probes (per-destination exhaustion) + port-less fail-closed
  collisions + drain-quarantine rejections;
- `xpf_userspace_interface_snat_registry_cap_exhaustion_total` — the
  per-address 64512 flow-registry cap AND the 256-retained-allocator cap
  (both "cannot create more registry state" events; Codex r4 minor 9 +
  nit 10 — the two §4.3 exhaustion modes are now counted distinctly). An
  optional `reason` label (`flow_cap` vs `allocator_cap`) is an
  implementation-time refinement, not a plan requirement (AGY r5 nit 1).
- `xpf_userspace_interface_snat_sync_identity_conflict_drops_total` —
  coordinator import-conflict drops (§5.6). Its doc text states that the
  series ALSO includes the BENIGN legacy-alias conflict drop from the
  legacy window (a fabric alias importing into its own base's identity —
  indistinguishable from a genuine conflict by construction, hence
  fail-closed there; on the negotiated-omission path aliases never
  conflict at all) — SMR r9 N17 — and that NON-ZERO counts are EXPECTED
  during a mixed-version rolling upgrade while receiving from legacy
  senders (AGY r14 nit 3).
- `xpf_userspace_session_sync_forward_wire_alias_ignored_total` —
  GO-side Prometheus counter for fabric forward-wire alias rows
  confirmed-dropped from the receiver-side quarantine (§5.6; a routine
  benign steady-state event for fabric-redirect sessions on the legacy
  window — operator-visible proof the discipline is active); and
  `xpf_userspace_session_sync_alias_quarantine_admitted_total` — GO-side
  counter for quarantine-timeout ADMISSIONS (genuine self-NAT /
  identity-NPTv6 / lost-base rows — Codex r14 nit 5: the collateral is
  its own series, not a note on the drop counter). The Rust-side
  `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS` going quiet for the same
  sessions confirms the companion-poisoning side fix.
`debug_log!` is feature-gated (afxdp/mod.rs:51) — test/dev aid only.
Exhaustion additionally rides the existing production NAT-failure event
path (`record_source_nat_failure`, nat_exception.rs:154). PAT'd sessions
are operator-visible through the already-generic session display. Registry
occupancy/holder introspection is a named follow-up, not this PR.

## 6. Public API preservation

Preserved byte-for-byte: `NatDecision`, `SourceNatLookup`, `SessionKey`,
the Go→helper snapshot
protocol (`SourceNATRuleSnapshot` and the NAT64 snapshot gain NO fields —
empty-pool is the NAT64 fail-closed channel), all CLI/gRPC surfaces.
NO wire change of any kind for the core fix; the fabric-alias
discipline adds ONE additive, old-peer-ignorable periodic
`syncMsgCapability` frame on a dedicated ticker (advertised by new
receivers; new senders omit alias derivation when it is present — old
peers on both sides see today's exact behavior; explicitly NOT a
handshake field, since unkeyed deployments bypass the handshake,
sync_auth.go:321).
Additive-only wire-visible changes (#1961-safe): the four helper-side
§5.8 status counters (three more — the alias-discipline counters —
are GO-side Prometheus, §5.8).
`SyncedSessionEntry` gains ONE additive HELPER-INTERNAL field
(`pub_token: u64`, the coordinator-local publication token of §5.6 —
stamped at publish inside the helper; it is NOT read from or written to
any Go-facing wire, and older in-image rows read as token 0).
The four helper-side §5.8 status counters are additive optional fields
(#1961-safe); the THREE Go-side §5.8 counters (alias confirmed-dropped,
alias quarantine-admitted, quarantine-overflow) are GO-side Prometheus
with no helper wire involvement (seven counters total).
Changed signatures are `pub(crate)`-internal only:
`match_source_nat_result_for_tuple` (+1 arg),
`match_source_nat_for_flow_result_at` (+1), `source_nat_decision_for_flow`
(+1), `source_nat_would_translate_fragment` (+1),
`release_source_nat_allocation` / `rollback_source_nat_allocation` /
`reserve_synced_source_nat_allocation` (+2 each: registry + worker id),
`publish_shared_session` (+1: registry — Codex r4 blocker 5),
`remove_shared_session` (+1: registry), the coordinator test helper, the
nine release sites' call expressions, the new
`install_synced_with_reserve` wrapper at the three sync-family install
sites, a NEW narrow read accessor `translated_tuple_of(key)` on
`SessionTable` for the staged-replacement pre-read (`entry_by_key` is
private, session/mod.rs:1093 — Codex r5 blocker 1), the
`MaterializeConflict` outcome type for the materialize wrapper,
`release_all_worker_markers` at the worker-join teardown,
the registry bulk-release at the wholesale-clear site, the pool-allocator
authoritative `addr_index` + per-index live counter + drain carry-over key,
the address-only mint paths' `addr_index` correction, the tuple-versioned
`(flow, translated)` record key + secondary flow index inside the
interface registry's allocator instances, and the transactional
shared-replacement
alias sweep inside `publish_shared_session`'s displacement handling. Go changes: the #5144
validator extension (dedup-by-address), the snapshot-builder overlap
marking (source pools + NAT64 empty-pool + the §5.7 derivation matrix),
the receiver-side signature-drop rule + delete-suppression set
(§5.6), the four helper-side status-counter mirrors + Describe
registration, the THREE Go-side counters (confirmed-dropped +
quarantine-admitted + overflow), and tests.

## 7. Hidden invariants the change must preserve

- **Core ownership invariant**: every reachable session owns exactly one
  translated identity, held continuously from BEFORE it is reachable
  (decision-time mint; coordinator pre-reserve; reserve-before-install
  wrapper; publish-time {Shared}) until AFTER it is not (holder set
  empties: all workers + shared canonical row + teardown marker sweeps).
- **Probe purity (both classes)**: `non_first_fragment == true` OR
  `tuple_unknown == true` mints NOTHING.
- **Single-CS mint**: identity check + insert under ONE `live` mutex
  acquisition; the exact PAT probe chunks at 64 with yields, a LOCAL start
  ordinal, and ONE mutation-epoch retry.
- **Idempotent re-entry**: a second packet of the same flow returns the
  existing translation; no double-mint.
- **Release symmetry**: every mint frees through the existing teardown
  sites — no new delete site; rollback frees pre-install aborted mints;
  holder set empties before the identity frees; wholesale worker teardown
  drops all worker markers; wholesale shared clears iterate-and-release.
- **Never-steal**: synced reserve fails rather than evict a different
  flow's live identity; `IdentityConflict` ABORTS the reserve (tri-state),
  never falls through to a second domain.
- **Reserve-before-install everywhere**: local mint precedes install;
  worker wrapper reserves first (drop on failure, rollback on refusal);
  coordinator pre-reserve precedes publication; materialize reserve
  conflict returns `MaterializeConflict` to an explicit recycle/drop
  branch — NEVER a lookup miss and never the cold-admission path
  (Codex r5 major 4 / r6 minor 4).
- **Continuous holding across tuple change**: the staged replacement
  protocol (§5.6) on tuple-versioned records never frees T_old before it
  is unreachable on every scope — coordinator: pre-reserve T_new →
  canonical replace → alias sweep of the displaced entry → −{Shared};
  worker: pre-read → reserve T_new → install/replace → −{Worker}; each
  owner decrements only its own marker.
- **Drain discipline**: drain markers install BEFORE the worker-visible
  RuntimeView store; NEW mints on an address quarantine in EVERY domain
  while any generation holds live allocations on it (pool skips the
  address in its loop, NAT64 likewise, interface fails closed); reserves
  are never quarantined (but are tri-state); the drain lift is one atomic
  critical section (no resurrection); `addr_index` is authoritative in
  every mint path.
- **Registry lifetime**: node-lifetime; atomic `or_insert_with` creation;
  reclamation only when address-absent AND live-empty (apply-time +
  opportunistic); cap 256 RETAINED with its own counter; release
  LOOKUP-ONLY.
- **Invariant scoping (SMR r5 N16)**: "continuous holding" excludes the
  queue/relay-or-expiry-bounded reverse-companion edge
  (`replicate_session_delete` enqueues commands — no strict deadline),
  which is identical in shape to shipped pool-mode discipline today.
- **Fabric-alias discipline (v15)**: on the new+new path the SENDER
  omits derived forward-wire aliases entirely (additive pre-data
  `syncMsgCapability` frame with a fail-safe unknown→derive lifecycle —
  zero alias traffic, zero collateral, genuine self-NAT and
  identity-NPTv6 rows flow normally). On the legacy window the RECEIVER
  quarantines signature-matching upserts (full rewritten-tuple signature
  with the mandatory NAT64 exclusion and NO disposition gate — the
  cluster codec carries no disposition field, so non-fabric
  identity-NPTv6 rows also quarantine and timeout-admit), confirms
  aliases ORDER-AGNOSTICALLY (check the current store for a sibling
  canonical base at quarantine insertion — the sender queues base first
  on open — and only wait for the base's arrival in the lossy-reorder
  case), and ADMITS everything else on timeout through the complete
  normal import path (generation checks, timestamp rebasing, bulk
  bookkeeping, coordinator reserve, helper dispatch). Delete suppression
  begins at confirmation and clears when the first delete for the key
  after the base's delete is consumed (the alias's own delete, queued
  after the base's on close) or on a short bound; a genuine direct row
  sharing the key whose delete arrives while suppressed strands until
  its own session timeout — bounded, and strictly safer than today's
  certain publish-time clobber (shared_ops.rs:907). No alias row ever
  reaches the helper's ownership machinery unvetted; the base session's
  own derived forward-wire index row (shared_ops.rs:943-957) serves
  every lookup the alias row served, and the broken synthesized-companion
  churn (a live shipped hazard, shared_ops.rs:750 + nat/mod.rs:106)
  closes wherever the alias never forms.
- **NatDecision freeze**: no new fields; `rewrite_src_port: Some(_)` is
  handled generically everywhere from pool mode.
- **Hot path**: established-flow transit untouched; zero new per-packet
  work; admission-only registry locks; 1:N multimaps return to len-1
  inline buckets for interface SNAT.
- **Logging**: no per-packet logging; security-relevant events ride §5.8
  counters.

## 8. Risk assessment

| Class | Rating | Notes |
|---|---|---|
| Behavioral regression | LOW-MED | Wire change only for wire-ambiguous flows (later collider PAT'd); non-colliding flows byte-identical incl. sub-1024 ports and cross-dst port sharing. Overlap foreclose marks misconfigured pools unusable and DRAINS live ones (interface mints on the overlapping address fail closed during the drain — an availability pause on a previously-misdelivering path). Import drop-on-conflict sacrifices individual synced flows rather than their confidentiality. Tuple-changing re-sync keeps T_old held until unreachable. Pinned tests at session/tests.rs:4560/4602 stay GREEN (direct-install pins bypass admission) — one re-pointed at a live collision class, one annotated (§9). Mixed-version HA window documented (§5.4). |
| Lifetime / borrow-checker | LOW | Registry is `Arc<PortAllocator>` clones out of coordinator-owned `RwLock` maps; the SessionManager placement precedent. |
| Performance regression | LOW | Admission-only: registry write-lock create (first use per address) or read; one `live` mutex identity mint per NEW interface-mode flow; PAT probe only on collision (chunked); drain probe O(1) on quarantined addresses only; publish/remove +1 idempotent holder op per forward session lifecycle (cold paths); sync import +1 mint per entry on the coordinator (throttled sweep); zero per-packet cost. |
| Architectural mismatch | LOW | Built verbatim on the shipped #5269 token machinery + #5144 validator pattern + SessionManager placement + #4518 drain carry-over + #1760-W3' counter plumbing; no new subsystem, no packet-path scan. |

## 9. Test plan

- `cargo build` clean; full `make test-rust` and `make test-go`;
  `make test` umbrella. Fleet cap: build with
  `CARGO_TARGET_DIR=/home/ps/cargo-target/research-6751`.
- New unit tests (nat/source.rs + allocator):
  preserve-first success; collision → PAT (distinct identities, distinct
  `reverse_wire_key`s, both flows' replies resolve to their OWN forward
  session); same port different servers BOTH preserve; TCP vs UDP same
  numeric port BOTH preserve; source port < 1024 preserved; ICMP same-id
  pair → second id translated; port-less GRE → token, second collider
  fail-closed; EXACT probe (local start ordinal: full cycle finds the one
  free candidate among shaped contiguous occupied runs — RED on the v2
  4096-budget design; genuine per-destination saturation → exhaustion;
  registry-cap vs per-destination exhaustion distinguished; concurrent
  mint/free with the mutation-epoch retry); idempotent re-entry;
  cross-rule same-egress collision detected; BOTH probe classes mint
  nothing; rollback frees; reserve_synced tri-state (NotThisDomain /
  Owned / IdentityConflict — the Codex r4 counterexample: draining pool
  owns T, interface import of T aborts, never falls through); nat64
  decisions bypass the source/interface scan; addr_index authoritative in
  every address-only mint path (pool [A,E] address-only flow on E counts
  against E, not A); tuple-versioned records (a flow holds T_old + T_new
  transiently during staged replacement; release matches (flow,
  translated) exactly; a different-tuple record is removed only by an
  explicit holder release when its holder set empties (never auto-dropped
  by a reserve — Codex r6 major 2 / r7 nit 6); transactional
  shared replacement (canonical replace sweeps the displaced entry's
  aliases — reverse_wire/reverse_canonical/forward_wire of T_old no
  longer resolvable — with COMPARE-AND-REMOVE ownership validation so a
  third-party occupant of T_old's derived slot is never swept — Codex r7
  major 4); fabric forward-wire alias discipline (new+new: a sender
  honoring the receiver's additive capability advertisement SKIPS the
  alias derivation branch entirely — zero alias upserts AND zero alias
  deletes on the wire, genuine self-NAT and identity-NPTv6 rows flowing
  normally with NO collateral (Codex r13's own "negotiated sender-side
  alias omission"); legacy window: signature-matching upserts QUARANTINE
  in pkg/cluster after decode before bulkRecv bookkeeping
  (sync_conn_read.go:110 ordering) — the full rewritten-tuple signature
  (forward ∧ sync-derived ∧ SNAT flag ∧ NOT NAT64 — decoded Nat64SnatV4
  exclusion per Codex r13 blocker 2, since a v4 NAT64 rewrite reformats
  as an IPv6 address and a legitimate NAT64 client at that address would
  otherwise match — ∧ key.src_ip ==
  rewrite_src ∧ (key.src_port == rewrite_src_port OR rewrite_src_port ==
  0) — the full-tuple term per Codex r13 major 3a, so bijective
  same-address PAT and same-IP static mapped-port sessions never match;
  NO disposition gate per Codex r14 blocker 1 — the cluster codec
  carries no disposition field, so non-fabric identity-NPTv6 rows also
  quarantine and timeout-admit);
  bulk bookkeeping is NOT gated (AGY r15 blocker 1 — quarantined keys are
  still recorded as received at decode time, so
  reconcileStaleSessions/ReconcileClusterBulk at BulkEnd never deletes a
  genuine self-NAT or identity-NPTv6 session as stale ~50ms after the
  bulk, before its 5s timeout admission could run; and the timeout
  admission's bookkeeping touch is guarded on a bulk being open — after
  BulkEnd the map is nil'd, sync.go:1090, so an unconditional write
  would panic);
  confirmation is ORDER-AGNOSTIC (Codex r14 blocker 2 — the sender queues
  the base FIRST on open, daemon_ha_userspace_stream.go:370/375/384, so
  the quarantine checks the CURRENT store for a sibling canonical base
  at INSERTION: forward-wire relation + identical decision + equal
  NON-ZERO RTFlowSessionID — and only waits for the base's arrival in
  the lossy-reorder alias-first case) → confirmed entries dropped +
  delete suppression that clears only when the FIRST delete for the key
  AFTER the base's delete is consumed (the alias's own delete — the
  exporter queues base-delete before alias-delete on close,
  daemon_ha_userspace_stream.go:398/403) or on a short bound;
  every quarantined entry RESOLVES AT ITS OWN BULK'S BulkEnd (Codex r15
  blocker 1 — no cross-epoch deferral: at BulkEnd the complete snapshot
  makes the sibling-base check definitive — still-matching entries with
  a sibling in the received set CONFIRM-alias and drop; everything else
  is ADMITTED through the complete normal import path — generation
  checks, timestamp rebasing, bulk bookkeeping, coordinator reserve,
  helper dispatch — in the same serialized pass BEFORE the bulk ACK and
  sync-hold release (sync_conn_read.go:240/244), so the receiver never
  ACKs while a genuine row is unresolved; incremental-delta entries
  (outside any bulk) resolve on a 5s fallback timer with the CURRENT
  store as definitive; ALL quarantine actions run as events on the
  receiver's SERIALIZED event loop — a timer only enqueues a wakeup,
  since the generation-check/install/record sequence is safe only
  single-threaded, sync_conn_gen.go:381)
  for the genuine self-NAT, identity-NPTv6 (no alias is ever derived
  for it, daemon_ha_userspace_convert.go:511), and lost-base cases
  (plus the Codex r16 lifecycle rules folded above: quarantine-cap
  OVERFLOW aborts the incomplete bulk without ACK (no eviction —
  payloads are not retained past decode) and its pinned entries drop
  fail-closed; a STALLED bulk hits the new per-bulk receive deadline
  and aborts the same way; a SUPERSEDING BulkStart drops the prior
  epoch's pinned entries fail-closed before overwriting the maps);
  the implementation parameter summary for the alias discipline:
  quarantine cap (4096, tunable per deployment at provisioning),
  incremental-delta fallback timeout (5s), AbortFenceTimeout (a small
  multiple of the disconnect callback's normal latency — AGY r19 nit),
  per-bulk receive deadline (new, named at implementation), and the
  abort-triggered per-peer reconnect backoff (base/cap, abort-only);
  a genuine direct row sharing the key whose delete arrives while
  suppression is active strands until its own session timeout
  (documented residual, strictly safer than today's certain
  publish-time clobber, shared_ops.rs:907); three Go-side counters
  (confirmed-dropped, quarantine-admitted, overflow); V4 AND
  V6 parity — AGY r10/r11 nit; `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS`
  no longer fires per sweep for a fabric-redirect SNAT session wherever
  the alias never forms — the pre-existing
  companion-displacement churn is gone — Codex r10/r11/r12 blockers
  resolved by removal); staged replacement
  (T_old held until unreachable;
  each owner drops only its own marker); uniform mint quarantine (a
  re-enabled edited pool cannot mint an identity an older draining
  generation owns — pool skips quarantined addresses in its address loop,
  interface fails closed; EVERY fixed-address mode fails closed when its
  selected address is quarantined, enumerated as separate test cases —
  address-persistent/sticky single-probe, port-translating persistent-NAT
  pinned-lease decision (allocator.rs:1114), address-only persistent
  (allocator.rs:1955), deterministic CGNAT (allocator.rs:1482),
  deterministic NAT64 (allocator.rs:1561) — Codex r7 minor 5 / r8 minor 3);
  materialize conflict returns
  MaterializeConflict (explicit recycle/drop branch, NEVER the
  cold-admission miss path — Codex r5 major 4); tuple-
  versioned secondary flow index (local mint re-entry returns the flow's
  locally-minted record across the staged overlap; reserve NEVER
  auto-drops a different-tuple record — Codex r6 major 2); holder completeness
  (sibling replica reap does not free the owner's identity — RED on the
  #6522 shape; replay re-reserve is a no-op; all-workers-reap with live
  shared canonical row does NOT free; materialize acquires via the wrapper;
  local publish acquires {Shared}; coordinator
  pre-reserve conflict drops the import; RESERVE-BEFORE-INSTALL: the
  delete/upsert/local-mint race leaves NO installed-unreserved duplicate;
  worker-join teardown drops all worker markers; stop_inner(false)
  reconcile replay re-acquires; wholesale clear iterate-and-releases every
  {Shared}; stop→rebind with a held identity); drain quarantine (overlap
  marked unusable; live pool session keeps its tuple in the draining
  allocator; interface mint on the address fails closed; drain completes →
  atomic lift → mints proceed; pool EDITED mid-drain → releases still
  reach the draining allocator via the drain-vec scan — AGY r4 major 2).
- Go validator tests: dedup-by-address (two interface rules, one WAN
  address → NO false rejection); interface-vs-source-pool overlap → strict
  reject + tolerant warn; interface-vs-NAT64-pool overlap → same;
  no-overlap pass.
- Go builder tests (the §5.7 derivation matrix): overlap via `to-zone`,
  via `to-interface`, via `to-routing-instance`, via UNSCOPED to-side
  (wildcard = all interfaces) — each marks the pool unusable / NAT64 pool
  empty; RUNTIME-resolved address (mocked buildLinkSnapshot); non-overlap
  unchanged.
- Existing pins: session/tests.rs:4560/4602 stay GREEN; ONE re-pointed at a
  live non-bijective class (DNAT-to-shared-backend), the OTHER annotated
  that direct-install bypasses admission; #4399/#4438/#5269/#5336 suites
  unchanged.
- Smoke (loss userspace cluster, lock protocol per CLAUDE.md): two test
  hosts behind interface-mode SNAT, same source port to the same target —
  both flows establish, distinct external ports on the WAN side (tcpdump),
  replies land on the correct host; same-id ping pair both get replies;
  `make test-failover`; bulk-sync/failover pin for the
  two-legacy-flows-one-identity import case (first reserves, second drops,
  failover kills only the second); helper-restart rehydration via HA
  re-sync pre-reserve.
- Counters: the seven §5.8 counters (four helper-side + three Go-side) bump exactly on their events;
  `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS` stays flat for the interface
  class.
- Docs sweep: docs/userspace-dataplane-architecture.md,
  docs/userspace-dataplane-gaps.md:44 row, `_Log.md`.

## 10. Out of scope (explicitly)

- Pool allocator holder fix (#6522) — the new registry ships with the
  holder model; pool keeps its known exposure until #6522 lands.
- Junos-literal always-PAT — larger wire change, no correctness gain.
- Config knobs for the interface-mode port range (fixed 1024-65535);
  registry occupancy/holder introspection (§5.8 follow-up).
- Quarantine-with-retry for import conflicts (adjudicated §5.6).
- #2387 session-identity enrichment — orthogonal; the colliding flows share
  every context.
- DNAT-to-shared-backend / NAT64 / static non-bijective classes — covered
  by the shipped 1:N multimaps.
- NAT64 fabric forward-wire alias ownership — NAT64 decisions bypass the
  interface registry (§5.3); their alias reserves keep today's
  never-steal graceful-skip. The cross-family alias-reconstruction
  concern (an alias deriving a different NatDecision from the padded v6
  slot, codec/wire.rs:182 + server/helpers/session_sync.rs:47) is a
  PRE-EXISTING NAT64-sync question, named here as a follow-up candidate
  (Codex r7 blocker 3, scoped out with the reviewers' option to re-open).
- ALG payload rewriting for PAT'd ports; netflow/syslog translated-port
  fields (already generic per §4 item 4 audit).

## 11. Open questions for adversarial review

1. Core invariant (top of doc, as scoped by SMR r5 N16's reverse-companion
   relay-lag note): name ONE remaining lifecycle path where a reachable
   session does not own its identity — the r4/r5 inventory (publication,
   tuple-changing re-sync on tuple-versioned records, drain transition
   with uniform mint quarantine, worker teardown, reconcile replay,
   transactional shared replacement with the derived-index sweep) is now
   covered in §5.3/§5.6/§5.7, and the fabric-alias class is removed from
   the ownership design entirely (§5.6, v11).
2. The v14 alias discipline (negotiated sender omission on new+new;
   receiver-side signature quarantine on the legacy window) rests on
   three verified claims: the explicit alias row is redundant with the
   base's derived forward-wire index row (walked independently by AGY
   r9/r11/r12/r13 and Codex r9/r10/r11/r12/r13); the full rewritten-tuple
   signature with the NAT64 exclusion and fabric gate false-positives on
   NOTHING except genuine self-NAT rows in the legacy window, and those
   are ADMITTED after the quarantine timeout (a delay, not a drop); and
   the base-lifecycle delete suppression is strictly safer-or-equal to
   today in every matrix cell (today the alias upsert clobbers a
   same-key occupant at publish with certainty, shared_ops.rs:907).
   Falsify any of the three with a consumer of the explicit alias row
   the derived row does not serve, a NAT class where the full signature
   still false-positives, or a delete-ordering where the
   base-lifecycle-keyed suppression strands a genuine row past its
   timeout. The capability transport is now fixed (dedicated periodic
   syncMsgCapability ticker, no alternatives) — is there any receiver
   state machine in pkg/cluster whose periodic cadence the ticker
   should SHARE rather than duplicate?
3. Tuple-versioned records (§5.3): confined to the interface registry's
   allocator instances, with pool allocators keeping today's flow-keyed
   shape and free-on-release semantics. Is the two-shape split coherent,
   or should pools adopt the tuple-versioned shape uniformly (which
   entangles #6522's open holder question)?
4. Uniform mint quarantine (§5.7): pool admission skips a quarantined
   address and tries the next pool address — graceful for multi-address
   pools, exhaustion when all are quarantined. Is skip-next the right
   pool-side posture, or should pool admission fail closed on the rule
   (like interface) while any of its addresses drains?
5. Preserve-first vs Junos-literal always-PAT: does any reviewer still
   demand literal parity?
6. Mixed-version window (§5.4): accept, or gate `SessionSyncProtocol`?
7. Is PLAN-KILL (option (c)) defensible for a High security finding given
   the mechanism is ~verbatim reuse of shipped machinery?
