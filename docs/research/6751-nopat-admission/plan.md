# #6751 plan — interface SNAT no-PAT admission: reserve-or-PAT the colliding translated tuple

- **Status**: DRAFT v4 — round-3 fold (Codex r3 blockers 1-4 + majors 5-7 +
  minor 8; AGY r3 majors 1-2 + nit 3; Claude SMR r3 M13-M15 all folded)
- **Issue**: #6751 (opus-review-001 R08, High, `bug`+`audit`+`security`) —
  interface SNAT admits indistinguishable no-PAT return tuples and sends
  replies to the FIRST session.
- **Base**: `ad9591177481` (origin/master at research start).
- **Scope**: `userspace-dp` Rust dataplane + Go snapshot-builder overlap
  foreclosure + Go commit-validator extension (§5.7) + additive optional
  status counters (§5.8). No breaking wire change, no `NatDecision`/
  `SourceNatLookup` shape change.
- **Core invariant** (round-3 reviewers' formulation, adopted): EVERY
  reachable session owns exactly one translated identity, held continuously
  from before it is reachable until after it is not — across admission,
  replication, materialization, re-reserve, reconcile replay, snapshot
  rebuilds, HA transitions, link stop→rebind cycles, and helper restart.

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
  normalizes source ports. It is also a deterministic insider primitive: a
  malicious internal host can deliberately squat a victim's (port, server)
  external identity (UDP/ICMP need no handshake), or brute-force the whole
  64512-port space against a victim server (§4 option (b) analysis).

If reviewers conclude the fix's churn exceeds the risk, PLAN-KILL is an
acceptable verdict — PLAN-KILL here means shipping option (c), status quo
plus documentation, and saying so on the issue.

## 3. What's already shipped / partially batched

| Prior work | What it gives this plan |
|---|---|
| #4399/#4438 1:N multimaps + validate-on-lookup | Retains both colliding handles; stays as defense-in-depth for the OTHER non-bijective classes (DNAT-shared-backend, NAT64, static). |
| **#5269/#5336/#5338/#5341/#6041/#6226** address-only occupancy token (`PortAllocator::reserve_address_only`, `address_only_owners`, `release_flow`/`rollback_flow` address_only arm) | THE mechanism option (a) is built on: identity-keyed occupancy `(protocol, translated_ip, translated_port, dst_ip, dst_port)`, ONE-mutex mint (no TOCTOU), idempotent re-entry, fail-closed collision, stale-tuple-drop on re-reserve (allocator.rs:1666-1676). Preserve AND PAT both mint this token shape; release/rollback verbatim (allocator.rs:1318/1392). |
| #5144 strict overlap validator (`natAllocOwner`/compiler_validate_strict_nat.go:2525-2576) + `pool_failure`/`PoolUnusable` fail-closed channel (nat_source.go:118-122; NAT64 native empty-pool fail-closed at nat64.rs:1123) | The two-layer foreclosure pattern §5.7 extends. |
| #4388/#4512 `reserve_synced_source_nat_allocation` + coordinator publish path (ha/session_import.rs) | The HA reservation points §5.6 makes transactional. |
| #4518 NAT64 allocator carry-over across reloads (`Nat64State::from_snapshots_with_previous`) | The drain-domain precedent for §5.7's quarantined-pool drain. |
| #4074/#4088 ICMP id translation; #1852 fragment gate + #2562/#5146 frag assoc + #6122 fail-closed probe | The ICMP/fragment stories, unchanged. |
| #4676 `gc_expired_chunked` (bounded work per mutex acquisition) | The §5.2 probe chunking discipline. |
| SessionManager coordinator-owned shared maps (coordinator/session_manager.rs:12 → worker/launch.rs:130) | The registry placement precedent. |
| #1760 W3' status-counter plumbing (protocol/control.rs:343, protocol_status.go:287, server/lifecycle.rs:228, server/helpers/status.rs:102, pkg/api/metrics.go:377, metrics_descriptors_userspace_session.go:27, metrics_userspace.go:677) | The additive-counters precedent §5.8 follows — full inventory (Codex r3 major 7). |
| **OPEN #6522** — sibling replica reap releases a live flow's SNAT allocation | The new registry's holder model (§5.6) is designed so this hazard cannot exist in it; pool-side fix remains #6522's own issue. |

## 4. Multiple Path Options (the design fork)

### Option (a) — reserve translated identity at admission; PAT the later collider (RECOMMENDED)

Interface-mode becomes "address-only occupancy with preserve-first and an
exact PAT fallback", built ENTIRELY on the shipped #5269 token machinery:

1. **Registry (node-lifetime, OUTSIDE ForwardingState)** — in the
   coordinator-owned shared-state home next to the three shared session maps
   (`SessionManager`, coordinator/session_manager.rs:12), cloned into every
   worker (`WorkerSharedDataplane::from_coord`, worker/launch.rs:130). Never
   rebuilt on commit; one `Arc<PortAllocator>` per egress address.
   `allocator_for` is ONE write-lock `entry(addr).or_insert_with(...)`
   returning the stored winner. Bounded lifetime: snapshot-apply reclamation
   (address absent from the new egress set AND `live_by_flow` empty), PLUS
   opportunistic reclaim when a release empties an absent address's
   allocator (AGY r3 nit 3); a cumulative cap of 256 CURRENTLY-RETAINED
   allocators (Codex r3 minor 8: retained cardinality, NOT ever-created —
   with its own cap-failure counter/reason); RELEASE is LOOKUP-ONLY
   (`allocator_if_present` — a static/foreign decision's release never
   creates an empty allocator).
2. **Occupancy model (identity-set, no bitmap claims)** — occupancy keyed on
   the FULL reverse identity `(protocol, egress_addr, port, dst_ip,
   dst_port)` (the shipped `AddressOnlyReverseKey`, allocator.rs:178-183):
   same source port to different servers → BOTH preserve; TCP vs UDP same
   numeric port → both preserve; source port < 1024 → preserved (only PAT
   candidates are drawn ≥ 1024); cross-destination port reuse allowed (the
   Junos-default OVERLOADING posture).
3. **Admission mint** (interface branch, nat/source.rs:1226), gated
   `!non_first_fragment && !tuple_unknown` (BOTH probe classes mint nothing):
   - **port-less protocol**: `alloc.reserve_address_only(flow, egress)` —
     Ok → Matched (address-only); Err → `Unavailable(AllocatorExhausted)`.
   - **port-bearing**: per-step single-mutex CS — (i) idempotent re-entry
     (`live_by_flow[flow]` → existing translation); (ii) identity-mint the
     PRESERVED tuple → Matched with `rewrite_src_port: None`; (iii)
     identity held by a different flow → EXACT PAT probe (Codex r3 major 5):
     capture ONE start ordinal from the allocator's atomic cursor, then walk
     `start + i mod 64512` LOCALLY (never re-calling the shared cursor
     mid-walk — concurrent callers cannot skip/revisit this walk's
     candidates), identity-minting `(proto, egress, candidate, dst,
     dst_port)` per candidate, at most 64 candidates per `live` mutex
     acquisition with a yield between chunks (#4676 discipline). A full
     cycle with no success means one of two EXACT failure modes, both
     reported `Unavailable(AllocatorExhausted)` and counted distinctly: the
     per-(egress,dst,dport) identity space is full, OR the per-address
     `live_by_flow` registry cap (64512) is consumed by flows to OTHER
     destinations (registry-cap exhaustion is NOT per-destination
     exhaustion — Codex r3 major 5a). Because chunks release the mutex, a
     candidate can free after its chunk passed: ONE mutation-epoch retry
     (if the allocator's mutation epoch advanced during the walk, re-walk
     once); a second failure is accepted as exhaustion-under-churn
     (documented transient, not a correctness violation — the
     linearizability boundary AGY r3 verified).
   - Preserved and PAT'd tokens share the SAME `address_only` record shape
     and the SAME release/rollback arms (allocator.rs:1332-1345/:1404-1418).
     No lock-free pre-claim exists; the AGY r1/SMR M5 race cannot occur.
4. **No session-index, lookup, flow-cache, or packet-rewrite changes** —
   translated identities unique per flow ⟹ the existing bijective fast path
   is correct; NO longer packet-path scan (per the review's guidance).
   Surface audit (verified POSITIVE by AGY r2 + Codex r2/r3):
   `rewrite_src_port: Some(_)` is already generic from pool mode on
   flow-cache descriptors (flow_cache.rs:586), conntrack publish
   (publish_conntrack.rs:197), gRPC render (server_sessions.go:1724),
   RT_FLOW (rt_flow.rs:82), HA conversion (daemon_ha_userspace_convert.go:357
   + protocol_ha.go:57).

Trade-offs: closes the security hole AND the availability hole; wire change
only for wire-ambiguous flows; (b)'s squatting DoS avoided (the victim PATs
around the squatter). Cost: registry + holder model + §5.7 foreclosure +
§5.8 counters.

### Option (b) — reserve-and-reject: fail the later collider closed

Identical machinery minus the PAT probe: identity-mint Err →
`Unavailable(AllocatorExhausted)`. Smallest diff (a strict subset of (a)'s);
internally consistent with pool `no-translation` (#5269). Costs: (i)
availability loss Junos does not have (same-id ICMP ping pair hard-fails the
second host); (ii) **identity-squatting DoS**: an insider mints a victim's
(source port, server) identity first and keeps it (or brute-forces all
64512), denying the victim indefinitely — converting a confidentiality bug
into an availability bug under the SAME attacker preconditions. Under (a)
the victim PATs around the squatter. (AGY r1 argued (b); AGY r2 re-evaluated
and now endorses (a); Codex r2/r3 endorse (a).)

### Option (c) — status quo + documentation

Keep the collision; document it. Zero diff; keeps a High-severity silent
misdelivery + hijack/squat primitive on a security-labeled issue.
Recommended AGAINST.

**Recommendation: option (a)** — preserve-first identity reservation + exact
chunked PAT probe + port-less fail-closed token + §5.7 two-layer foreclosure
with drain. All three reviewers have endorsed (a) since round 2.

## 5. Concrete design

### 5.1 Registry type and placement

```rust
/// Node-lifetime interface-mode SNAT identity registry, coordinator-owned
/// next to the shared session maps (SessionManager,
/// coordinator/session_manager.rs:12), cloned into every worker
/// (worker/launch.rs:130). ONE allocator per egress ADDRESS (never per
/// rule, never per VRF: the reverse lookup namespace is global-by-address —
/// SessionKey carries no VRF/zone/ifindex, session/key.rs:9, #2387 open).
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
    /// Snapshot-apply: drop allocators absent from the new egress set with
    /// an EMPTY live_by_flow; same predicate applied opportunistically when
    /// a release empties an absent allocator. Cap 256 RETAINED.
    fn reclaim_absent(&self, live_egress: &FastSet<IpAddr>);
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
    // §5.7 drain quarantine: fail closed while a draining pool/NAT64 domain
    // holds live allocations on this address (new-mint gate ONLY — reserves
    // for existing sessions are NOT quarantined).
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
    match alloc.allocate_interface_identity(flow, rewrite_src, now_ns) {
        // per §4.3: idempotent re-entry -> existing; mint preserved identity;
        // else exact full-cycle probe (local start ordinal, 64-chunk yields,
        // one mutation-epoch retry); preserved -> rewrite_src_port None,
        // PAT'd -> Some(candidate); exhaustion (two exact modes) -> Unavailable
    }
}
```

### 5.3 Release / rollback / reserve-synced

`release_source_nat_allocation_with_mode` and
`reserve_synced_source_nat_allocation` each gain the registry parameter.
Scan order stays pools-first (Codex r3 blocker 2's provenance concern is
resolved by the DRAIN model, §5.7: a preserved pool session's identity
belongs to the DRAINING pool domain, so pool-first scan order is CORRECT
during drain; after drain the pool is gone and only the interface domain
remains — no window where both domains claim ownership of new mints).
Interface arm is LOOKUP-ONLY, flow-keyed discrimination
(`live_by_flow[flow]` + `existing.translated == translated`,
allocator.rs:1318-1330) so pool address-only and interface-mode decisions
each miss the other's registry. The nine release sites thread the worker's
stable `worker_id: u32` (`BindingWorker.worker_id`, worker/mod.rs:108-112).
Synced reserve mints the exact synced identity and mirrors `reserve_flow`'s
stale-tuple-drop (allocator.rs:1666-1676) with the PER-HOLDER-OWNER
decrement discipline (SMR r3 M14): each site decrements only its own
marker — the coordinator's drop decrements `{Shared}`, a worker's drop
decrements `{Worker(W)}`; cross-site orphan windows are bounded by the
upsert fanout and are leak-safe direction (never free-early).

### 5.4 HA / mixed-version

Synced decisions carry `rewrite_src_port` over the existing wire — no wire
change. Mixed-version rolling upgrade:
- new active → old standby: the old standby IMPORTS the PAT'd decision fine
  (the field is generic — protocol_ha.go:57, daemon_ha_userspace_convert.go:357;
  AGY r1's "mis-parse" claim withdrawn in AGY r2). The old standby never
  RESERVES it (its reserve skips non-pool rules, nat/source.rs:921).
  Post-failover it can admit a no-PAT flow onto the synced tuple —
  collision probability equal to the pre-existing bug's, not worse.
- old active → new standby: the pair the old active admitted collides on
  the standby exactly as on the active; the new standby pre-reserves the
  first and DROPS the second import on conflict (§5.6); post-failover the
  dropped flow re-establishes. Pinned bulk-sync/failover test (§9, Codex r3
  major 6).
- Verdict: an ACCEPTED, documented rolling-upgrade window bounded by the
  pre-existing bug's probability, closing when both nodes upgrade.
  `SessionSyncProtocol` gating (pkg/upgrade/imageversions.go:162) rejected:
  hard-gating breaks HA sync during any rolling upgrade — worse.

### 5.5 Fragments / ICMP

First fragment carries L4 → normal admission; the forward fragment assoc
(#2562/#5146) stores the decision (with any PAT port) and non-first
fragments consult it; out-of-order non-first-first fragments drop fail-closed
via the #6122 probe (probe purity per §5.2); ICMP echo id collision →
second id translated through the #4074 `rewrite_src_port` machinery (RFC
5508 §3.1) including incremental checksum.

### 5.6 Holder ownership and transactional reserve (the lifecycle-complete model)

The holder set on each flow's `live_by_flow` record is
`FxHashSet<HolderId>`, `HolderId = Worker(u32) | Shared`:

- **Local admission**: mint at decision time inserts `{Worker(W)}` —
  RESERVE-BEFORE-INSTALL by construction (the mint precedes the session
  install; install-refused aborts roll back via the existing rollback
  sites, poll_descriptor/mod.rs:2313/2374/2472/2634/4902).
- **Sync import — TRANSACTIONAL at the coordinator**: the coordinator
  pre-reserves the identity (+`{Shared}`) BEFORE `publish_shared_session`
  (ha/session_import.rs:131-137 publishes before fanning worker upserts at
  :233). On identity CONFLICT the import is DROPPED (not published, not
  queued; counted by §5.8's
  `xpf_userspace_interface_snat_sync_identity_conflict_drops_total` + one
  Debug line per drop) — fail-closed: the standby never holds a session it
  cannot own; post-failover the flow re-establishes. The pre-reserve gates
  `is_reverse`. Bulk-sync replay is idempotent (`{Shared}` set-absorbed;
  a tuple CHANGED re-import hits the §5.3 stale-tuple-drop with the
  per-holder-owner decrement). The HA-fidelity DoS (an attacker on the
  standby's local segments squatting a synced identity so every refresh
  import loses; failover then kills that flow) is EXPLICITLY ACCEPTED and
  EXPOSED (the counter) — the alternatives are worse: install-unreserved
  restores the confidentiality bug post-failover; quarantine-with-retry
  holds table state for a session that still cannot forward at failover
  (Codex r3 major 6 adjudication).
- **Worker-side sync install — RESERVE-BEFORE-INSTALL** (Codex r3 blocker 3;
  v3's install-then-reserve wrapper plus the delete/upsert race produced an
  installed-but-unreserved duplicate): the single
  `install_synced_with_reserve(...)` wrapper = (1) reserve/+`{Worker(W)}`
  (idempotent-hits the coordinator's pre-reserved record); on reserve
  FAILURE → DO NOT install (drop the command, count, Debug); (2) install;
  on install refusal → release the just-added holder (rollback). Used by
  ALL THREE sync-family install sites (AGY r3 verified the inventory
  complete): `WorkerCommand::UpsertSynced` (commands/upsert_synced.rs:65),
  `materialize_shared_session_hit` (session_glue/mod.rs:1130),
  `WorkerCommand::UpsertLocal` (session_glue/mod.rs:808 tunnel prewarm).
  With reserve-first, the v3 race (coordinator delete removes `{Shared}`
  before a queued upsert; a local mint claims the identity; the stale
  upsert arrives) fails at the upsert's RESERVE — nothing installs — no
  unreserved duplicate.
- **Shared-map lifetime — pinned to the CANONICAL map** (SMR r3, refining
  AGY r3 major 1): the `{Shared}` holder rides the `shared_sessions`
  canonical map (keyed by session key, shared_ops.rs:905-909), NOT the
  reverse indexes. Canonical-map displacement is same-key (the same logical
  session re-publishing — refresh/promote/RG-migration), which the holder
  SET absorbs idempotently; reverse-index displacement (shared_ops.rs:921/
  :932) drops only an index row and is NOT a holder event. The closed
  removal inventory (SMR r3 M13): the seven `remove_shared_session` callers
  (session_delta.rs:436/446 — note the locally-owned reap reaches removal
  VIA THE CLOSE-DELTA RELAY, not at reap time; promote.rs:181;
  session_glue/mod.rs:587/938/945; session_import.rs:314/329;
  local_delivery.rs:91), the canonical same-key displacement (set-absorbed,
  non-event), the reverse-index displacement (non-event), and the wholesale
  clears — next bullet.
- **Wholesale clears — ITERATE-AND-RELEASE first** (AGY r3 major 2 +
  Codex r3 blocker 4): `stop_inner(true)`/`clear_synced_state`
  (coordinator/mod.rs:756-766) `.clear()`s all three shared maps — reached
  in PRODUCTION via `stop_workers` link stop→rebind cycles
  (server/handlers/stop_workers.rs:7), and the node-lifetime registry
  survives. Before clearing, walk the canonical map and `−{Shared}` every
  forward entry holding an interface-mode reserve (bulk release helper on
  the registry); only then clear. Test: stop→rebind with a held interface
  identity (§9).
- **Releases**: the nine release sites remove the releasing worker's
  `{Worker(W)}`; the identity's token frees when the holder set empties.
  Saturating-decrement clamp + flow+tuple-keyed release (a stray decrement
  can never touch a different flow's allocation).
- **Neutral paths**: promote (promote.rs:99 mutate-in-place), demote
  (install.rs:568 origin flip), #1752 in-place refresh — NO reserve/release
  calls, holder-neutral by construction.
- Net effect: the identity survives while ANY entry replica or shared entry
  lives node-wide — the #6522 hazard cannot exist in this registry.

### 5.7 Cross-domain overlap foreclosure with DRAIN (Codex r3 blockers 1-2)

The interface registry, source-pool allocators, and NAT64 allocators are
DISJOINT occupancy domains; a source pool (or NAT64 pool) containing an
egress interface address reintroduces the collision across the seam.
Foreclosure at BOTH layers, plus a DRAIN discipline for already-live
sessions (Codex r3 blocker 1: marking a pool unusable stops only NEW pool
admissions; preserved/live pool sessions keep their tuples — teardown.rs:54
preserves shared sessions across reconcile, coordinator/mod.rs:810 replays,
and local worker-table sessions persist across snapshot swaps — so the
interface domain must not mint on the overlapping address until the old
domain drains):

1. **Commit validator** (#5144 extension): interface-mode egress addresses
   join the owner set DEDUPED BY ADDRESS (multi-rule same-WAN configs must
   not false-reject). Overlap → REJECT at strict commit; WARN on tolerant
   load / peer-sync (#5837/#1960 no-brick doctrine).
2. **Snapshot builder + DRAIN** (the runtime layer — interface snapshots
   resolve LIVE kernel addresses, interfaces.go:455-465, so DHCP/
   externally-installed addresses can overlap a configured pool invisibly
   to config validation; DHCP triggers a full recompile on address change,
   daemon_dhcp.go:73/85):
   - Any pool address overlapping an interface address that an
     interface-mode rule can egress on marks that POOL unusable
     (`pool_failure`/`PoolUnusable` — fail-closed NEW pool admissions,
     nat_source.go:118-122 precedent). NAT64: the builder emits the
     overlapping NAT64 rule with an EMPTY pool — the shipped native
     fail-closed path (nat64.rs:1123) — plus the validator warning names
     the overlap (Codex r3 blocker 2: no `PoolUnusable` field exists on the
     NAT64 snapshot, protocol_nat.go:319/protocol/nat.rs:312; empty-pool is
     the channel).
   - The dataplane RETAINS the quarantined pool's previous allocator as a
     DRAINING domain (the #4518 NAT64 carry-over precedent): releases from
     already-live sessions keep draining it; a per-address-index live
     counter (small allocator addition; mint +1 / release −1) makes the
     drain observable in O(1). Reserve/release scans for POOL decisions
     keep consulting the draining allocator (their identities belong to
     that domain until empty).
   - The interface registry records `draining[E] = [draining allocators]`;
     interface MINTS on E fail closed
     (`InterfaceOverlapDraining`, counted) while any draining allocator
     holds live allocations on E; the quarantine lifts when the drain
     empties, and the drained allocator is then dropped. Interface
     RESERVES (synced imports of existing sessions) are NOT quarantined —
     they are ownership claims for sessions that already exist.
   - Race window (documented): a NEW interface mint on E racing the
     drain-marker installation at snapshot-apply can claim an identity a
     preserved session still holds; the preserved session's replay/import
     reserve then conflicts and DROPS that session (fail-closed per §5.6) —
     availability loss bounded to the racing session, never misdelivery.

### 5.8 Observability (additive, production)

Three ADDITIVE optional counters on the existing helper status wire,
plumbed via the FULL #1760-W3' precedent (Codex r3 major 7 inventory:
protocol/control.rs:343 + server/lifecycle.rs:228 init +
server/helpers/status.rs:102 refresh on the Rust side;
protocol_status.go:287 + pkg/api/metrics.go:377 +
metrics_descriptors_userspace_session.go:27 + metrics_userspace.go:677 on
the Go/Prometheus side; additive per #1961):
- `xpf_userspace_interface_snat_pat_collisions_total` — identity-mint
  conflicts that took the PAT probe;
- `xpf_userspace_interface_snat_identity_exhaustion_total` — completed
  full-cycle probes (per-destination exhaustion) + registry-cap exhaustion
  + port-less fail-closed collisions + drain-quarantine rejections;
- `xpf_userspace_interface_snat_sync_identity_conflict_drops_total` —
  coordinator import-conflict drops (§5.6) — a High security fix that
  deliberately discards HA state must expose it (Codex r3 major 7).
`debug_log!` is feature-gated (afxdp/mod.rs:51) — test/dev aid only.
Exhaustion additionally rides the existing production NAT-failure event
path (`record_source_nat_failure`, nat_exception.rs:154). PAT'd sessions
are operator-visible through the already-generic session display. Registry
occupancy/holder introspection is a named follow-up, not this PR.

## 6. Public API preservation

Preserved byte-for-byte: `NatDecision`, `SourceNatLookup`, `SessionKey`,
`SyncedSessionEntry`, the HA session-sync wire, the Go→helper snapshot
protocol (`SourceNATRuleSnapshot` gains NO fields; the NAT64 snapshot gains
NONE — empty-pool is the fail-closed channel), all CLI/gRPC surfaces.
Additive-only wire change: the three §5.8 status counters (optional fields,
#1961-safe). Changed signatures are `pub(crate)`-internal only:
`match_source_nat_result_for_tuple` (+1 arg),
`match_source_nat_for_flow_result_at` (+1), `source_nat_decision_for_flow`
(+1), `source_nat_would_translate_fragment` (+1),
`release_source_nat_allocation` / `rollback_source_nat_allocation` /
`reserve_synced_source_nat_allocation` (+2 each: registry + worker id), the
coordinator test helper, the nine release sites' call expressions, the new
`install_synced_with_reserve` wrapper at the three sync-family install
sites, the registry bulk-release helper at the wholesale-clear site, and
the pool-allocator per-index live counter + drain carry-over. Go changes:
the #5144 validator extension (dedup-by-address), the snapshot-builder
overlap marking (source pools + NAT64 empty-pool), the three status-counter
mirrors, and tests.

## 7. Hidden invariants the change must preserve

- **Core ownership invariant**: every reachable session owns exactly one
  translated identity, held continuously from BEFORE it is reachable
  (decision-time mint; coordinator pre-reserve; reserve-before-install
  wrapper) until AFTER it is not (holder set empties: all workers + shared
  canonical row released).
- **Probe purity (both classes)**: `non_first_fragment == true` OR
  `tuple_unknown == true` mints NOTHING.
- **Single-CS mint**: identity check + insert under ONE `live` mutex
  acquisition; the exact PAT probe chunks at 64 candidates per acquisition
  with yields, a LOCAL start ordinal (no shared-cursor skips), and ONE
  mutation-epoch retry (second failure = exhaustion-under-churn,
  documented).
- **Idempotent re-entry**: a second packet of the same flow returns the
  existing translation; no double-mint.
- **Release symmetry**: every mint frees through the existing teardown
  sites — no new delete site; rollback frees pre-install aborted mints;
  holder set (workers + shared) empties before the identity frees;
  wholesale clears iterate-and-release first.
- **Never-steal**: synced reserve fails rather than evict a different
  flow's live identity; conflict at import DROPS the synced entry.
- **Reserve-before-install everywhere**: local mint precedes install;
  worker wrapper reserves first (drop on failure, rollback on install
  refusal); coordinator pre-reserve precedes publication.
- **Drain discipline**: interface mints quarantine on an overlapping
  address while any draining domain holds live allocations on it; reserves
  are never quarantined; the draining allocator is carried (not dropped)
  until empty.
- **Registry lifetime**: node-lifetime; atomic `or_insert_with` creation;
  reclamation only when address-absent AND live-empty (apply-time +
  opportunistic at release); cap 256 RETAINED with its own failure
  counter; release LOOKUP-ONLY.
- **NatDecision freeze**: no new fields; `rewrite_src_port: Some(_)` is
  handled generically everywhere from pool mode.
- **Hot path**: established-flow transit untouched; zero new per-packet
  work; admission-only registry locks; 1:N multimaps return to len-1
  inline buckets for interface SNAT.
- **Logging**: no per-packet logging; security-relevant events (PAT probe,
  exhaustion, quarantine, import-conflict drop) ride §5.8 counters.

## 8. Risk assessment

| Class | Rating | Notes |
|---|---|---|
| Behavioral regression | LOW-MED | Wire change only for wire-ambiguous flows (later collider PAT'd); non-colliding flows byte-identical incl. sub-1024 ports and cross-dst port sharing. Overlap foreclose marks misconfigured pools unusable and DRAINS live ones (interface mints on the overlapping address fail closed during the drain — an availability pause on a previously-misdelivering path, not a silent failure). Import drop-on-conflict sacrifices individual synced flows rather than their confidentiality. Pinned tests at session/tests.rs:4560/4602 stay GREEN (direct-install pins bypass admission) — one re-pointed at a live collision class, one annotated (§9). Mixed-version HA window documented (§5.4). |
| Lifetime / borrow-checker | LOW | Registry is `Arc<PortAllocator>` clones out of a coordinator-owned `RwLock` map; the SessionManager placement precedent. |
| Performance regression | LOW | Admission-only: registry write-lock create (first use per address) or read; one `live` mutex identity mint per NEW interface-mode flow; PAT probe only on collision (chunked); drain probe O(1) per mint on quarantined addresses only; sync import +1 mint per entry on the coordinator (throttled sweep); zero per-packet cost. |
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
  registry-cap exhaustion distinguished from per-destination exhaustion —
  Codex r3 major 5; concurrent mint/free with the mutation-epoch retry);
  idempotent re-entry; cross-rule same-egress collision detected; BOTH
  probe classes mint nothing; rollback frees; reserve_synced mirrors exact
  identity, never steals, stale-tuple re-reserve drops old identity with
  per-holder-owner decrement; holder completeness (sibling replica reap
  does not free the owner's identity — RED on the #6522 shape; replay
  re-reserve is a no-op; all-workers-reap with live shared canonical row
  does NOT free; materialize acquires via the wrapper; coordinator
  pre-reserve conflict drops the import; RESERVE-BEFORE-INSTALL: the
  delete/upsert/local-mint race leaves NO installed-unreserved duplicate —
  Codex r3 blocker 3's deterministic test; wholesale clear
  iterate-and-releases every {Shared}; stop→rebind with a held identity);
  drain quarantine (overlapping pool marked unusable; live pool session
  keeps its tuple in the draining allocator; interface mint on the address
  fails closed; drain completes → mints proceed).
- Go validator tests: dedup-by-address (two interface rules, one WAN
  address → NO false rejection); interface-vs-source-pool overlap → strict
  reject + tolerant warn; interface-vs-NAT64-pool overlap → same;
  no-overlap pass.
- Go builder tests: pool overlapping a RUNTIME-resolved interface address
  (mocked buildLinkSnapshot) → pool_unusable; NAT64 overlapping rule →
  emitted with EMPTY pool (native nat64.rs:1123 fail-closed); non-overlap
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
  failover kills only the second — Codex r3 major 6); helper-restart
  rehydration via HA re-sync pre-reserve.
- Counters: the three §5.8 counters bump exactly on their events;
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
- Quarantine-with-retry for import conflicts (adjudicated §5.6: drop is
  cleaner and fails closed).
- #2387 session-identity enrichment — orthogonal; the colliding flows share
  every context.
- DNAT-to-shared-backend / NAT64 / static non-bijective classes — covered
  by the shipped 1:N multimaps.
- ALG payload rewriting for PAT'd ports; netflow/syslog translated-port
  fields (already generic per §4 item 4 audit).

## 11. Open questions for adversarial review

1. Core invariant (top of doc): name ONE remaining lifecycle path where a
   reachable session does not own its identity — admission, replication,
   materialize, re-reserve, reconcile replay, snapshot rebuild, HA
   transition, stop→rebind, helper restart are all covered in §5.6/§5.7.
2. Drain model (§5.7): the per-index live counter on the pool allocator is
   the only new allocator state beyond the token shape. Is O(1) drain
   observability worth it, or should the quarantine probe scan
   `live_by_flow` filtering `translated.ip == E` (O(pool flows), quarantine
   window only)?
3. Import drop-on-conflict (§5.6): is the accepted HA-fidelity DoS
   correctly priced, or do reviewers now prefer quarantine-with-retry
   despite the failover equivalence?
4. Reserve-before-install wrapper: the reserve failure drops the worker
   command — should a dropped `UpsertSynced` ALSO remove the coordinator's
   `{Shared}` (it was pre-reserved for an entry that will never install on
   this worker)? Current spec: no — `{Shared}` rides the canonical map row,
   which the peer's delete-sync removes; per-worker reserve is additive
   only. Attack.
5. Exact probe: is ONE mutation-epoch retry the right bound, or should the
   walk retry until the epoch is stable across a full cycle (unbounded
   under adversarial churn)?
6. Registry cap 256 retained — right bound, or derive from the #5877-style
   aggregate capacity budget?
7. Preserve-first vs Junos-literal always-PAT (Codex r2: Juniper documents
   always-PAT): does any reviewer still demand literal parity?
8. Is PLAN-KILL (option (c)) defensible for a High security finding given
   the mechanism is ~verbatim reuse of shipped machinery?
