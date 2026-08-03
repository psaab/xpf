# #6751 plan — interface SNAT no-PAT admission: reserve-or-PAT the colliding translated tuple

- **Status**: DRAFT v6 — round-5 fold (Codex r5 blockers 1-3 + major 4;
  AGY r5 nits 1-2; Claude SMR r5 N16 all folded)
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
  (SMR r5 N16): the relay-bounded reverse-companion edge (ms-scale
  delete-replication lag) is excluded — identical in shape to shipped
  pool-mode discipline today; see §5.6.

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
  - the stale-tuple-drop removes the `(flow, T_old)` record ONLY when its
    holder set is empty; otherwise it decrements only the caller's own
    marker (per-holder-owner discipline) and leaves the record;
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

The holder set on each flow's `live_by_flow` record is
`FxHashSet<HolderId>`, `HolderId = Worker(u32) | Shared`:

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
    pre-existing stale-alias residual for any tuple-changing republish)
    → `−{Shared}` on T_old. T_old stays held by its `{Worker}` markers
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
- **Neutral paths**: promote (promote.rs:99), demote (install.rs:568),
  #1752 in-place refresh — NO reserve/release calls.
- **Reverse-companion lag (documented inherited window, SMR r5 N16)**:
  forward and reverse companions of one flow can live in DIFFERENT
  workers' tables (internal and external tuples hash differently). The
  identity frees when the holder set empties (forward reap −{Worker} +
  canonical removal −{Shared}), while a reverse companion elsewhere is
  holder-neutral and lingers until its own reap or the delete-replication
  relay (`replicate_session_delete`; the session_delta.rs:436-446 removal
  covers both keys) reaches it — a relay-bounded (ms-scale) window in
  which a re-minted identity's reply could land on the lingering reverse
  entry. This window exists TODAY for pool mode (pool port freed at
  forward reap while the reverse companion lingers; the #3011 recycle
  FIFO is only a reuse-delay, also churnable), so the change does not
  widen it; closing it belongs to the session-teardown domain, not this
  NAT-admission fix. The core invariant statement is scoped accordingly:
  continuous holding on every scope EXCEPT the relay-bounded
  reverse-companion edge, which matches shipped pool discipline.
- Net effect: the identity survives while ANY entry replica or shared
  canonical row lives node-wide — the #6522 hazard cannot exist in this
  registry.

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
     quarantined), NAT64 likewise, interface-mode mints fail closed
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
additive per #1961):
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
  coordinator import-conflict drops (§5.6).
`debug_log!` is feature-gated (afxdp/mod.rs:51) — test/dev aid only.
Exhaustion additionally rides the existing production NAT-failure event
path (`record_source_nat_failure`, nat_exception.rs:154). PAT'd sessions
are operator-visible through the already-generic session display. Registry
occupancy/holder introspection is a named follow-up, not this PR.

## 6. Public API preservation

Preserved byte-for-byte: `NatDecision`, `SourceNatLookup`, `SessionKey`,
`SyncedSessionEntry`, the HA session-sync wire, the Go→helper snapshot
protocol (`SourceNATRuleSnapshot` and the NAT64 snapshot gain NO fields —
empty-pool is the NAT64 fail-closed channel), all CLI/gRPC surfaces.
Additive-only wire change: the four §5.8 status counters (optional fields,
#1961-safe). Changed signatures are `pub(crate)`-internal only:
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
`(flow, translated)` record key inside the interface registry's allocator
instances, and the transactional shared-replacement alias sweep inside
`publish_shared_session`'s displacement handling. Go changes: the #5144
validator extension (dedup-by-address), the snapshot-builder overlap
marking (source pools + NAT64 empty-pool + the §5.7 derivation matrix),
the four status-counter mirrors + Describe registration, and tests.

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
  coordinator pre-reserve precedes publication; materialize returns
  miss-on-failure.
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
  relay-bounded reverse-companion edge (ms-scale delete-replication lag),
  which is identical in shape to shipped pool-mode discipline today.
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
  translated) exactly; stale-drop removes the record only when its holder
  set is empty, else decrements only the caller's marker); transactional
  shared replacement (canonical replace sweeps the displaced entry's
  aliases — reverse_wire/reverse_canonical/forward_wire of T_old no
  longer resolvable); staged replacement (T_old held until unreachable;
  each owner drops only its own marker); uniform mint quarantine (a
  re-enabled edited pool cannot mint an identity an older draining
  generation owns — pool skips quarantined addresses in its address loop,
  interface fails closed); materialize conflict returns
  MaterializeConflict (explicit recycle/drop branch, NEVER the
  cold-admission miss path — Codex r5 major 4); holder completeness
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
- Counters: the four §5.8 counters bump exactly on their events;
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
- ALG payload rewriting for PAT'd ports; netflow/syslog translated-port
  fields (already generic per §4 item 4 audit).

## 11. Open questions for adversarial review

1. Core invariant (top of doc, as scoped by SMR r5 N16's reverse-companion
   relay-lag note): name ONE remaining lifecycle path where a reachable
   session does not own its identity — the r4/r5 inventory (publication,
   tuple-changing re-sync on tuple-versioned records, drain transition
   with uniform mint quarantine, worker teardown, reconcile replay,
   transactional shared replacement with alias sweep) is now covered in
   §5.3/§5.6/§5.7.
2. Tuple-versioned records (§5.3): confined to the interface registry's
   allocator instances, with pool allocators keeping today's flow-keyed
   shape and free-on-release semantics. Is the two-shape split coherent,
   or should pools adopt the tuple-versioned shape uniformly (which
   entangles #6522's open holder question)?
3. Transactional shared replacement (§5.6): the alias sweep on canonical
   displacement also fixes a PRE-EXISTING stale-alias residual for any
   tuple-changing republish (today's publish inserts new aliases and never
   removes the displaced entry's). Should that sweep be pinned as its own
   regression test independent of the interface-mode work?
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
