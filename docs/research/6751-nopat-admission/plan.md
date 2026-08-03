# #6751 plan — interface SNAT no-PAT admission: reserve-or-PAT the colliding translated tuple

- **Status**: DRAFT v3 — round-2 fold (Codex r2 blockers 1-3 + majors 4-6 +
  minor 7 + nit 8; AGY r2 blockers 1-2 + majors 3-4 + minors 5-6 + nit 7;
  Claude SMR r2 M9-M12 all folded)
- **Issue**: #6751 (opus-review-001 R08, High, `bug`+`audit`+`security`) —
  interface SNAT admits indistinguishable no-PAT return tuples and sends
  replies to the FIRST session.
- **Base**: `ad9591177481` (origin/master at research start).
- **Scope**: `userspace-dp` Rust dataplane + Go snapshot-builder overlap
  foreclosure + Go commit-validator extension (§5.7) + two additive optional
  status counters (§5.8). No breaking wire change, no `NatDecision`/
  `SourceNatLookup` shape change.

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
  presented as an INTENTIONAL xpf semantic — wire-stable for non-colliding
  flows — not claimed literal Junos parity (Junos allocates unconditionally).
- Collision frequency today: requires same protocol + same source port +
  same server + simultaneous liveness. Rare for random-ephemeral TCP, but
  realistic for ICMP echo (Linux ping reuses small per-socket identifiers;
  two hosts pinging one target with the same id is common), for UDP services
  with pinned source ports, and for any middlebox that normalizes source
  ports. It is also a deterministic insider primitive: a malicious internal
  host can deliberately squat a victim's (port, server) external identity
  (UDP/ICMP need no handshake), and can brute-force the whole 64512-port
  space against a victim server to deny a pinned-port victim (§4 option (b)
  analysis).

If reviewers conclude the fix's churn exceeds the risk, PLAN-KILL is an
acceptable verdict — PLAN-KILL here means shipping option (c), status quo
plus documentation, and saying so on the issue.

## 3. What's already shipped / partially batched

| Prior work | What it gives this plan |
|---|---|
| #4399/#4438 1:N multimaps + validate-on-lookup | Retains both colliding handles; stays as defense-in-depth for the OTHER non-bijective classes (DNAT-shared-backend, NAT64, static). |
| **#5269/#5336/#5338/#5341/#6041/#6226** address-only occupancy token (`PortAllocator::reserve_address_only`, `address_only_owners`, `release_flow`/`rollback_flow` address_only arm) | THE mechanism option (a) is built on: identity-keyed occupancy `(protocol, translated_ip, translated_port, dst_ip, dst_port)`, ONE-mutex mint (no TOCTOU — Codex r2 verified allocator.rs:1727), idempotent re-entry, fail-closed collision, and a stale-tuple-drop discipline on re-reserve (allocator.rs:1666-1676). Preserve AND PAT both mint this token shape, so release/rollback are verbatim reuse (Codex r2 verified allocator.rs:1318/1392). |
| #5144 strict overlap validator (`natAllocOwner`/`validateNATPoolExternalTupleOverlapStrict`, compiler_validate_strict_nat.go:2525-2576) + `pool_failure`/`PoolUnusable` fail-closed channel (nat_source.go:118-122) | The two-layer foreclosure pattern §5.7 extends: commit-time reject for static overlap, snapshot-build-time fail-closed for runtime overlap. |
| #4388/#4512 `reserve_synced_source_nat_allocation` (upsert_synced.rs:91) + coordinator publish path (ha/session_import.rs) | The HA reservation points §5.6 makes transactional (coordinator pre-reserve before publish). |
| #4074/#4088 ICMP Query Identifier translation (pool mode, RFC 5508 §3.1) | The ICMP-id sub-case rides the same `rewrite_src_port` rewrite + checksum path. |
| #1852 fragment gate + #2562/#5146 forward fragment assoc + #6122 flowless-fragment fail-closed probe | The fragment story: decision-driven assoc for PAT'd flows, read-only probe preserved (Codex r2 verified both probe classes complete). |
| #4676 `gc_expired_chunked` (bounded work per mutex acquisition, yield between chunks) | The contention discipline for the §5.2 exact probe. |
| SessionManager coordinator-owned shared maps (coordinator/session_manager.rs:12, cloned into every worker at worker/launch.rs:130) | The placement precedent for the node-lifetime registry. |
| #1760 W3' status-counter plumbing (`NAT_REVERSE_KEY_SHARED_DISPLACEMENTS` → protocol/control.rs:343 + protocol_status.go:287) | The additive-counters precedent §5.8 follows. |
| **OPEN #6522** — sibling replica reap releases a live flow's SNAT allocation | The new registry's holder model (§5.6) is designed so this hazard cannot exist in it; pool-side fix remains #6522's own issue. |

## 4. Multiple Path Options (the design fork)

### Option (a) — reserve translated identity at admission; PAT the later collider (RECOMMENDED)

Interface-mode becomes "address-only occupancy with preserve-first and an
exact PAT fallback", built ENTIRELY on the shipped #5269 token machinery:

1. **Registry (node-lifetime, OUTSIDE ForwardingState)** — lives in the
   coordinator-owned shared-state home next to the three shared session maps
   (`SessionManager`, coordinator/session_manager.rs:12), cloned into every
   worker with the same `WorkerSharedDataplane::from_coord` mechanism
   (worker/launch.rs:130). Never rebuilt on commit; one
   `Arc<PortAllocator>` per egress address. `allocator_for` is ONE
   write-lock `entry(addr).or_insert_with(...)` returning the stored winner
   (Codex r2 major 4: a read-miss/create/write pattern can mint two
   allocators for one address). Bounded lifetime: at snapshot-apply, an
   allocator whose address is ABSENT from the new egress set AND whose
   `live_by_flow` is empty is reclaimed; a cumulative allocator cap (256)
   fails new-address mints closed (config-abuse bound); RELEASE is
   LOOKUP-ONLY — a static/foreign decision's release never creates an empty
   allocator (Codex r2 major 4).
2. **Occupancy model (identity-set, no bitmap claims)** — occupancy keyed on
   the FULL reverse identity `(protocol, egress_addr, port, dst_ip,
   dst_port)` — exactly the shipped `AddressOnlyReverseKey`
   (`nat/allocator.rs:178-183`). Consequences:
   - same source port to different servers: distinct identities → BOTH
     preserve (wire change only for genuinely ambiguous pairs);
   - TCP vs UDP same numeric port: protocol is in the key → both preserve;
   - source port < 1024 (incl. small ICMP ids): identity map is not
     range-bounded → preserved; only PAT candidates are drawn ≥ 1024;
   - cross-destination port reuse is allowed — the Junos-default
     OVERLOADING posture, not the off posture.
3. **Admission mint** (interface branch, nat/source.rs:1226), gated
   `!non_first_fragment && !tuple_unknown` (BOTH probe classes mint nothing
   and return today's address-only `Matched`; Codex r2 verified the caller
   inventory complete):
   - **port-less protocol** (GRE/ESP/AH/OSPF/HOPOPT):
     `alloc.reserve_address_only(flow, egress)` — Ok → Matched
     (address-only); Err → `Unavailable(AllocatorExhausted)` fail-closed
     (verbatim #5269 semantics).
   - **port-bearing** (TCP/UDP/ICMP-query): ONE mutex critical section per
     step — (i) idempotent re-entry: `live_by_flow[flow]` hit returns the
     existing translation (RSS/flow-hash steering pins one flow's packets to
     one worker; this path covers worker-reconfig and HA replays); (ii)
     identity-mint the PRESERVED tuple `(proto, egress, src_port, dst,
     dst_port)` — success → Matched with `rewrite_src_port: None`;
     (iii) identity held by a different flow → EXACT PAT probe
     (Codex r2 major 5 + AGY r2 major 4/5): walk the FULL 64512-candidate
     cycle from the allocator's atomic round-robin cursor, identity-minting
     `(proto, egress, candidate, dst, dst_port)` per candidate; first
     success → Matched with `rewrite_src_port: Some(candidate)`; a
     completed cycle with no success == GENUINE per-(egress,dst,dport)
     exhaustion (exact, no probability — the v2 "statistically exhaustive"
     wording and the #3011 recycle-FIFO comparison are WITHDRAWN:
     `try_next_port` is a deterministic counter, allocator.rs:944-958, and
     the recycle FIFO at allocator.rs:508/621 never sees identity tokens).
     Contention discipline (#4676 precedent): at most 64 candidate probes
     per `live` mutex acquisition, releasing and re-acquiring between
     chunks, so a probing admission never pins the per-address mutex across
     its full walk (AGY r2 major 4). Contention is scoped PER EGRESS
     ADDRESS, and the common case is zero probes (preserve succeeds).
   - The preserved and PAT'd tokens are the SAME `address_only` record
     shape in the SAME `address_only_owners` map with `live_by_flow[flow]
     = (egress, port)`, `address_only: true` — the SHIPPED
     `release_flow`/`rollback_flow` address_only arm frees either verbatim
     (`nat/allocator.rs:1332-1345`, `:1404-1418`). No bitmap bit is ever
     claimed; the full-cycle cursor's wrap gives reuse distance (a freed
     port is re-candidated only after the cursor traverses the cycle).
     No lock-free pre-claim exists, so the AGY r1/SMR M5 race cannot occur.
4. **Capacity**: per-address allocator
   `PortAllocator::new(1, 1024, 65535)` → `max_tracked_flows` 64512,
   enforced by the existing `live_by_flow.len()` check inside
   `reserve_address_only`; port-less and PAT'd tokens consume the same cap.
   Sync-import reserve mirrors the pool #4388 posture and does NOT cap (HA
   fidelity — documented policy choice).
5. **Release/rollback/reserve symmetry**: the NINE production release sites
   (reap `loop_body/mod.rs:1625`; five admission-abort rollbacks
   `poll_descriptor/mod.rs:2313/2374/2472/2634/4902`; synced delete
   `session_glue/commands/delete_synced.rs:38`; translated-sync purge
   `session_glue/promote.rs:194`; terminal teardown
   `session_glue/mod.rs:563`) all call
   `release_source_nat_allocation_with_mode` (nat/source.rs:781), extended:
   after the pool-rule loop releases nothing, consult the registry
   (LOOKUP-ONLY) keyed by `nat.rewrite_src` and run the same
   `release_flow`/`rollback_flow` with
   `translated = (rewrite_src, rewrite_src_port.unwrap_or(key.src_port))`.
   Discrimination is FLOW-keyed: `release_flow` matches
   `live_by_flow[flow]` AND `existing.translated == translated`
   (`allocator.rs:1318-1330`), so pool address-only and interface-mode
   decisions — byte-identical at release time — each miss the other's
   registry. The dormant RST-teardown path (`session_glue/mod.rs:908`,
   unreachable while `should_teardown_tcp_rst` returns false at :893) is
   explicitly EXCLUDED from the invariant. Reverse companions neither
   reserve nor release (both helpers gate `is_reverse`,
   nat/source.rs:789/874 — Codex r2 verified).
6. **No session-index, lookup, flow-cache, or packet-rewrite changes**: once
   translated identities are unique per flow, the existing bijective fast
   path is correct. NO longer packet-path scan (per the review's guidance).
   Surface audit (verified POSITIVE by AGY r2 + Codex r2):
   `rewrite_src_port: Some(_)` is already handled generically from pool
   mode on every downstream surface — flow-cache descriptor copy
   (`flow_cache.rs:586`), conntrack publish (`publish_conntrack.rs:197`),
   gRPC session render (`server_sessions.go:1724`), RT_FLOW event records
   (`rt_flow.rs:82`), HA conversion (`daemon_ha_userspace_convert.go:357`
   + `protocol_ha.go:57`).

Trade-offs: closes the security hole AND the availability hole (later
collider PATs, never drops for capacity reasons short of genuine
per-destination exhaustion); wire behavior changes ONLY for flows that are
ambiguous on the wire today; (b)'s identity-squatting DoS (below) is avoided
because the victim PATs around the squatter. Cost: the registry + holder
model + the §5.7 foreclosure + §5.8 counters.

### Option (b) — reserve-and-reject: fail the later collider closed

Identical machinery minus the PAT probe: the identity-mint Err maps straight
to `Unavailable(AllocatorExhausted)`.

Trade-offs: smallest possible diff (a strict subset of (a)'s); internally
consistent with pool `no-translation` (#5269). Cost: (i) availability loss
Junos does not have — the same-id ICMP ping pair hard-fails the second host;
(ii) **identity-squatting DoS**: an insider who learns a victim's
(source port, server) pair mints the identity first and keeps re-opening it,
denying the victim's flow every time — and a brute-force variant squats the
WHOLE 64512-port space against a victim server with 64512 short-lived flows,
denying a pinned-port victim indefinitely. (b) converts a confidentiality
bug into an availability bug under the SAME attacker preconditions. Under
(a) the victim PATs around the squatter and keeps service. (Round-1 AGY
argued (b) for a High security issue; round-2 AGY re-evaluated and now
states option (a) is the correct architecture.)

### Option (c) — status quo + documentation

Keep the collision; document it; keep the pinned tests. Zero diff; keeps a
High-severity silent misdelivery + hijack/squat primitive on a
security-labeled issue. Presented for completeness; recommended AGAINST.

**Recommendation: option (a)** — preserve-first identity reservation + exact
chunked PAT probe + port-less fail-closed token + §5.7 two-layer foreclosure.
All three round-2 reviewers converge on (a). (b) is the documented retreat.

## 5. Concrete design

### 5.1 Registry type and placement

```rust
/// Node-lifetime interface-mode SNAT identity registry, owned by the
/// coordinator next to the shared session maps (SessionManager,
/// coordinator/session_manager.rs:12) and cloned into every worker
/// (WorkerSharedDataplane::from_coord, worker/launch.rs:130). ONE allocator
/// per egress ADDRESS (never per rule, never per VRF: the reverse lookup
/// namespace is global-by-address — SessionKey carries no VRF/zone/ifindex,
/// session/key.rs:9, #2387 open — so the allocator must be at least as
/// coarse as the lookup key; (address, VRF) keying would let two VRF
/// allocators emit one globally-indexed tuple).
pub(crate) struct InterfaceNatAllocators {
    map: RwLock<FxHashMap<IpAddr, Arc<PortAllocator>>>, // 1-address each, 1024-65535
}
impl InterfaceNatAllocators {
    /// ONE write-lock entry().or_insert_with() — the stored winner is
    /// always returned (no read-miss/create/write split).
    fn allocator_for(&self, egress: IpAddr) -> Arc<PortAllocator>;
    /// LOOKUP-ONLY release path: None when no allocator exists (static /
    /// foreign / pool decisions) — never creates.
    fn allocator_if_present(&self, egress: IpAddr) -> Option<Arc<PortAllocator>>;
    /// Snapshot-apply reclamation: drop allocators absent from the new
    /// egress set with an EMPTY live_by_flow; cumulative cap 256.
    fn reclaim_absent(&self, live_egress: &FastSet<IpAddr>);
}
```

Address-only keying also serializes the cross-VRF same-address corner: two
VRFs sharing an egress address produce byte-identical reverse tuples no
index can separate, so the second VRF's colliding flow PATs instead of
silently colliding. Identical PRE-NAT tuples in overlapping VRFs remain
#2387's problem (SourceNatFlowKey lacks routing context, nat/source.rs:144)
— out of scope, named.

### 5.2 Admission mint

`match_source_nat_result_for_tuple` gains `iface_allocs: &InterfaceNatAllocators`,
threaded through `match_source_nat_for_flow_result_at`
(afxdp/forwarding/nat.rs:104), `source_nat_decision_for_flow`
(poll_descriptor/nat_exception.rs:24), the #6122 probe
(nat_exception.rs:96), and the coordinator test helper
(coordinator/status.rs:556). The #1377 "exactly two fail-closed decision
sites" textual guard (userspace-dp/tests/snat_contract_doc_guard.rs:53)
counts decision SITES, not signatures — unchanged (Codex r2 verified). The
interface branch:

```rust
if rule.interface_mode {
    let Some(rewrite_src) = (egress addr of the packet's family) else {
        return Unavailable(InterfaceNoEgressAddress);        // #5688, unchanged
    };
    if non_first_fragment || tuple_unknown {
        return Matched(address-only decision);   // BOTH probe classes: mint nothing
    }
    let alloc = iface_allocs.allocator_for(rewrite_src);     // atomic or_insert_with
    if port_less {
        return match alloc.reserve_address_only(flow, rewrite_src) {
            Ok(_)  => Matched(address-only decision),
            Err(r) => Unavailable(for_rule(rule, r)),         // second collider: fail closed
        };
    }
    match alloc.allocate_interface_identity(flow, rewrite_src, now_ns) {
        // 64-probe chunks per live-mutex acquisition, yield between chunks:
        //   idempotent re-entry -> existing translation
        //   else mint preserved identity (proto, egress, src_port, dst, dst_port)
        //   else exact full-cycle probe minting (proto, egress, cand, dst, dst_port)
        // success port==src_port -> rewrite_src_port None (preserved)
        // success port!=src_port -> Some(port) (PAT'd)
        // full cycle, no success -> Unavailable(AllocatorExhausted)  [EXACT]
    }
}
```

### 5.3 Release / rollback / reserve-synced

`release_source_nat_allocation_with_mode` and
`reserve_synced_source_nat_allocation` each gain the registry parameter.
Pool loop first (unchanged), interface arm second (LOOKUP-ONLY via
`allocator_if_present`), flow-keyed discrimination per §4 item 5. The nine
release sites thread the worker's stable `worker_id: u32`
(`BindingWorker.worker_id`, worker/mod.rs:108-112 — a worker owns multiple
bindings; the reap sweep is worker/table-scoped) for the holder decrement
(§5.6). Synced reserve mints the exact synced identity
(`translated.port = rewrite_src_port.unwrap_or(key.src_port)`) and mirrors
`reserve_flow`'s stale-tuple-drop (allocator.rs:1666-1676): a re-reserve
whose synced tuple CHANGED drops the old identity and decrements this
worker's holder on it first (AGY r2 blocker 2 — replace-time leak).

### 5.4 HA / mixed-version

Synced decisions carry `rewrite_src_port` over the existing wire — no wire
change. Mixed-version rolling upgrade:
- new active → old standby: the old standby IMPORTS the PAT'd decision fine
  (the field is generic — protocol_ha.go:57 carries `NATSrcPort`,
  populated whenever source NAT is present,
  daemon_ha_userspace_convert.go:357; AGY r1's "mis-parse / fail to install"
  claim was re-examined and WITHDRAWN in AGY r2 / Codex r2). The old standby
  never RESERVES it (its reserve skips non-pool rules, nat/source.rs:921).
  Post-failover it can admit a no-PAT flow onto the synced tuple —
  collision probability equal to the pre-existing bug's, not worse.
- old active → new standby: the pair the old active admitted collides on
  the standby exactly as it did on the active; the new standby reserves the
  first, and on conflict drops the second import (§5.6 — the flow's session
  is simply not synced; it re-establishes post-failover).
- Verdict: an ACCEPTED, documented rolling-upgrade window bounded by the
  pre-existing bug's probability, closing when both nodes upgrade.
  `SessionSyncProtocol` gating (pkg/upgrade/imageversions.go:162) was
  considered and rejected: hard-gating breaks HA session sync during any
  rolling upgrade — worse than the window.

### 5.5 Fragments / ICMP

First fragment carries L4 → normal admission; the forward fragment assoc
(#2562/#5146) stores the decision (with any PAT port) and non-first
fragments consult it (the same decision-driven path pool PAT uses);
out-of-order non-first-first fragments drop fail-closed via the #6122 probe
(unchanged, probe purity per §5.2); ICMP echo id collision → second id
translated through the #4074 `rewrite_src_port` machinery (RFC 5508 §3.1)
including incremental checksum.

### 5.6 Holder ownership and transactional reserve (Codex r2 blockers 2-3, AGY r2 blocker 1, SMR M9-M11)

The holder set on each flow's `live_by_flow` record is
`FxHashSet<HolderId>` where `HolderId = Worker(u32) | Shared` — a worker's
stable `worker_id` for table entries, and a `Shared` marker for the
shared-map entry:

- **Local admission**: mint at decision time inserts `{Worker(W)}` (W =
  admitting worker). Install-refused aborts roll back via the existing
  rollback sites (Codex r2 verified poll_descriptor/mod.rs:2372/:4902).
- **Sync import — TRANSACTIONAL at the coordinator** (Codex r2 blocker 2):
  the coordinator pre-reserves the identity (+`{Shared}`) BEFORE
  `publish_shared_session` (ha/session_import.rs:131-137 currently publishes
  before fanning worker upserts at :233). On identity CONFLICT the import
  is DROPPED (not published, not queued; counted + Debug log) — fail-closed:
  the standby never holds a session it cannot own, and post-failover the
  flow re-establishes under the new active. The pre-reserve gates
  `is_reverse` (reverse entries skip, mirroring nat/source.rs:874; SMR M10).
  Bulk sync cost: one mutex'd identity mint per imported entry on the
  coordinator — cold path, throttled sweep (SMR M10, documented).
- **Worker-side sync install**: every sync-family install routes through
  ONE wrapper (SMR M9) —
  `install_synced_with_reserve(sessions, iface_allocs, worker_id, install,
  allow_replace)` = install, then reserve/+{Worker(W)} for forward entries
  (`is_reverse` skips). Used by ALL THREE sync-family install sites:
  `WorkerCommand::UpsertSynced` (commands/upsert_synced.rs),
  `materialize_shared_session_hit` (session_glue/mod.rs:1122 — AGY r2
  blocker 1: it bypassed reserve entirely), and `WorkerCommand::UpsertLocal`
  (session_glue/mod.rs:778 tunnel prewarm). The worker reserve idempotent-
  hits the coordinator's pre-reserved identity (+{W} on the same record);
  a stale-tuple re-reserve drops the old identity with the holder decrement
  (§5.3).
- **Shared-map lifetime**: +`{Shared}` at `publish_shared_session`,
  −`{Shared}` at `remove_shared_session` (the pre-reserve IS the publish
  acquisition for synced entries; locally-admitted entries acquire
  `{Shared}` at their publish). This closes Codex r2 blocker 3's fatal
  sequence: all worker copies of a peer-synced entry stale-reap (−{W}
  each; peer-synced expiry emits no Close delta, session/expire.rs:342-344,
  so the shared entry remains) — `{Shared}` still holds, the identity is
  NOT freed, a new flow cannot claim it, and a later shared-map
  rematerialize is consistent. The identity frees only when no worker
  entry AND no shared entry references it; a stale shared entry delays
  free until shared-removal (delete-sync / shared-GC) — leak-safe
  direction, never free-early.
- **Releases**: every one of the nine release sites removes the releasing
  worker's `{Worker(W)}` (worker id threaded per §5.3); the identity's
  token frees when the holder set empties. Saturating-decrement rule: a
  −{W} for an absent holder Debug-logs and clamps; release stays
  flow+tuple-keyed so a stray decrement can never touch a different flow's
  allocation.
- **Neutral paths**: promote (promote.rs:99 mutate-in-place), demote
  (install.rs:568 origin flip), and #1752 in-place refresh make NO
  reserve/release calls — holder-neutral by construction (Codex r2
  verified "correctly holder-neutral once a real holder exists").
- **Delete-sync vs queued-upsert ordering** (SMR M11): a coordinator delete
  (−{Shared}) can precede a still-queued worker `UpsertSynced`; that worker
  then installs +{W} for a peer-deleted entry, released at the worker's own
  reap. Bounded (entry lifetime), safe direction (held, not freed early) —
  documented, not "fixed".
- Net effect: the identity survives while ANY entry replica or shared entry
  lives node-wide — the #6522 hazard cannot exist in this registry.
  Pool-mode's equivalent fix remains #6522's own issue.

### 5.7 Cross-domain overlap foreclosure, two layers (Codex r2 blocker 1, major 6)

The interface registry, source-pool allocators, and NAT64 allocators are
DISJOINT occupancy domains; a source pool (or NAT64 pool) containing an
egress interface address reintroduces the collision across the seam.
Foreclosure at BOTH layers:

1. **Commit validator** (#5144 extension,
   `validateNATPoolExternalTupleOverlapStrict`): interface-mode egress
   addresses join the owner set, DEDUPED BY ADDRESS (Codex r2 major 6 —
   "one owner per rule" would false-reject ordinary multi-rule configs
   resolving to one WAN address; the registry's actual ownership
   granularity is the address, so owners are distinct interface egress
   addresses, carrying rule refs for the diagnostic string). Overlap →
   REJECT at strict commit; WARN on tolerant load / peer-sync
   (#5837/#1960 no-brick doctrine).
2. **Snapshot builder** (the runtime layer the validator cannot see —
   Codex r2 blocker 1: interface snapshots resolve LIVE kernel addresses,
   pkg/dataplane/userspace/interfaces.go:455-465 `buildLinkSnapshot`, so
   DHCP/externally-installed addresses can overlap a configured pool
   invisibly to config validation; and the tolerant path installs overlap
   with only a warning): when building the source-NAT/NAT64 snapshot, any
   pool address overlapping an interface address that an interface-mode
   rule can egress on marks that POOL unusable via the existing
   `pool_failure`/`PoolUnusable` fail-closed channel (nat_source.go:118-122
   precedent — the dataplane then reports `Unavailable` on the pool rule,
   never mints). Policy: the pool loses (a pool containing the box's own
   interface address is operator error; interface addresses are runtime
   reality the box cannot disclaim). NAT64 pools: same treatment in the
   NAT64 builder. With overlap foreclosed at BOTH layers, each translated
   address belongs to exactly ONE domain, which ALSO resolves the HA
   reserve provenance ambiguity (pool-scan-then-interface-scan order
   becomes unambiguous).

### 5.8 Observability (Codex r1 major 9 / r2 minor 7, AGY r2 minor 6)

Two ADDITIVE optional counters on the existing helper status wire, plumbed
via the #1760-W3' precedent (Rust side protocol/control.rs:343; Go mirror
protocol_status.go:287; additive per #1961 — old Go ignores unknown fields,
old helper omits):
- `xpf_userspace_interface_snat_pat_collisions_total` — identity-mint
  conflicts that took the PAT probe;
- `xpf_userspace_interface_snat_identity_exhaustion_total` — completed
  full-cycle probes (genuine per-destination exhaustion) plus port-less
  fail-closed collisions.
`debug_log!` is feature-gated (afxdp/mod.rs:51) and is NOT production
observability (Codex r2 minor 7) — it stays a test/dev aid only.
Exhaustion additionally rides the existing production NAT-failure event
path (`record_source_nat_failure`, nat_exception.rs:154). PAT'd sessions
are operator-visible through the already-generic session display
(`show security flow session` renders `rewrite_src_port`). Registry
occupancy/holder introspection is a named follow-up, not this PR.

## 6. Public API preservation

Preserved byte-for-byte: `NatDecision`, `SourceNatLookup`, `SessionKey`,
`SyncedSessionEntry`, the HA session-sync wire, the Go→helper snapshot
protocol (`SourceNATRuleSnapshot` gains NO fields), all CLI/gRPC surfaces.
Additive-only wire change: the two §5.8 status counters (optional fields,
#1961-safe). Changed signatures are `pub(crate)`-internal only:
`match_source_nat_result_for_tuple` (+1 arg),
`match_source_nat_for_flow_result_at` (+1), `source_nat_decision_for_flow`
(+1), `source_nat_would_translate_fragment` (+1),
`release_source_nat_allocation` / `rollback_source_nat_allocation` /
`reserve_synced_source_nat_allocation` (+2 each: registry + worker id), the
coordinator test helper, the nine release sites' call expressions, and the
new `install_synced_with_reserve` wrapper at the three sync-family install
sites. Go changes: the #5144 validator extension + the snapshot-builder
overlap foreclosure + the two status-counter mirrors + tests.

## 7. Hidden invariants the change must preserve

- **Probe purity (both classes)**: `non_first_fragment == true` OR
  `tuple_unknown == true` mints NOTHING (#6122 contract +
  nat/source.rs:1109 synthetic wrapper; Codex r2 verified complete).
- **Single-CS mint**: identity check + insert under ONE `live` mutex
  acquisition (the `reserve_address_only` shape); no lock-free pre-claim
  exists to race the insert. The exact PAT probe chunks at 64 candidates
  per acquisition and yields between chunks (#4676 discipline).
- **Idempotent re-entry**: a second packet of the same flow returns the
  existing translation; no double-mint.
- **Release symmetry**: every mint frees through the existing teardown
  sites — no new delete site; rollback frees pre-install aborted mints;
  holder set (worker + shared) empties before the identity frees.
- **Never-steal**: synced reserve fails rather than evict a different
  flow's live identity; conflict at import DROPS the synced entry
  (transactional, §5.6) instead of installing an unreserved one.
- **Holder completeness**: every forward-entry install path acquires (local
  mint, or the single `install_synced_with_reserve` wrapper at all three
  sync-family sites); every removal path releases (the nine sites);
  promote/demote/materialize-origin/refresh are call-free neutral.
- **Registry lifetime**: node-lifetime; atomic `or_insert_with` creation;
  snapshot-apply reclamation only when address-absent AND live-empty;
  cumulative cap; release LOOKUP-ONLY.
- **NatDecision freeze**: no new fields; `rewrite_src_port: Some(_)` on an
  interface-mode decision is the only new observable state and every
  consumer handles it from pool mode (§4 item 6 audit).
- **Hot path**: established-flow transit untouched; zero new per-packet
  work; admission-only registry `RwLock`; 1:N multimaps return to len-1
  inline buckets for interface SNAT.
- **Logging**: no per-packet logging; PAT transitions count via §5.8;
  conflict-drop at import is one Debug line per dropped entry (bulk-sync
  bounded).

## 8. Risk assessment

| Class | Rating | Notes |
|---|---|---|
| Behavioral regression | LOW-MED | Wire change only for flows ambiguous on the wire today (later collider PAT'd); non-colliding flows byte-identical incl. sub-1024 ports and cross-dst port sharing. Overlap foreclose marks misconfigured pools unusable (operator-visible failure replaces silent misdelivery). Pinned tests at session/tests.rs:4560/4602 stay GREEN (direct-install pins bypass admission) — one re-pointed at a live collision class, one annotated (§9). Mixed-version HA window documented (§5.4). |
| Lifetime / borrow-checker | LOW | Registry is `Arc<PortAllocator>` clones out of a coordinator-owned `RwLock` map; the SessionManager placement precedent. |
| Performance regression | LOW | Admission-only: registry write-lock create (first use per address) or read; one `live` mutex identity mint per NEW interface-mode flow; PAT probe only on collision (chunked, cold); sync import +1 mint per entry on the coordinator (throttled sweep); zero per-packet cost. |
| Architectural mismatch | LOW | Built verbatim on the shipped #5269 token machinery + #5144 validator pattern + SessionManager placement + #1760-W3' counter plumbing; no new subsystem, no packet-path scan. |

## 9. Test plan

- `cargo build` clean; full `make test-rust` and `make test-go`;
  `make test` umbrella. Fleet cap: build with
  `CARGO_TARGET_DIR=/home/ps/cargo-target/research-6751`.
- New unit tests (nat/source.rs + allocator):
  preserve-first success (identity minted, `rewrite_src_port` None, release
  frees, later flow re-preserves); collision → PAT (distinct identities,
  distinct `reverse_wire_key`s, both flows' replies resolve to their OWN
  forward session); same port different servers BOTH preserve; TCP vs UDP
  same numeric port BOTH preserve; source port < 1024 preserved; ICMP
  same-id pair → second id translated; port-less GRE → token, second
  collider fail-closed; exact probe (full cycle finds the one free
  candidate among shaped contiguous occupied runs — RED on the v2
  4096-budget design; full cycle on a genuinely saturated destination →
  `AllocatorExhausted`); idempotent re-entry; cross-rule same-egress
  collision detected (one registry); BOTH probe classes mint nothing;
  rollback frees; reserve_synced mirrors exact identity, never steals,
  stale-tuple re-reserve drops old identity with holder decrement (AGY r2
  blocker 2); holder completeness ({Worker}+{Shared}: sibling replica reap
  does not free the owner's identity — RED on the #6522 shape; replay
  re-reserve is a no-op; all-workers-reap with live shared entry does NOT
  free (Codex r2 blocker 3); last-holder reap frees; materialize path
  acquires via the wrapper (AGY r2 blocker 1); coordinator pre-reserve
  conflict drops the import (Codex r2 blocker 2)).
- Go validator tests: interface-egress-address dedup-by-address (two
  interface rules resolving to one WAN address do NOT false-reject —
  Codex r2 major 6); interface-vs-source-pool overlap → strict reject +
  tolerant warn; interface-vs-NAT64-pool overlap → same; no-overlap pass.
- Go builder tests: pool overlapping a RUNTIME-resolved interface address
  (mocked buildLinkSnapshot) → pool_unusable fail-closed; NAT64 pool same;
  non-overlap unchanged.
- Existing pins: session/tests.rs:4560/4602 stay GREEN; ONE re-pointed at a
  live non-bijective class (DNAT-to-shared-backend) so the multimap pin
  covers an admission-reachable class, the OTHER annotated that
  direct-install bypasses admission; the #4399/#4438/#5269/#5336 suites
  unchanged.
- Smoke (loss userspace cluster, lock protocol per CLAUDE.md): two test
  hosts behind interface-mode SNAT, same source port to the same target —
  both flows establish, distinct external ports observed on the WAN side
  (tcpdump), replies land on the correct host; same-id ping pair both get
  replies; `make test-failover` (HA reserve adjacency). Helper-restart
  rehydration: restart the helper on the standby, verify reserves rebuild
  via HA re-sync pre-reserve.
- Counters: `xpf_userspace_interface_snat_pat_collisions_total` bumps
  exactly on collision; `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS` stays flat
  for the interface class.
- Docs sweep: docs/userspace-dataplane-architecture.md (interface-mode
  bullet + #4399 1:N section collision-class list),
  docs/userspace-dataplane-gaps.md:44 row, `_Log.md`.

## 10. Out of scope (explicitly)

- Pool allocator holder fix (#6522) — the new registry ships with the
  holder model; pool keeps its known exposure until #6522 lands.
- Junos-literal always-PAT (translate every interface-mode admission) —
  larger wire change, no correctness gain (§2/§4 document preserve-first as
  the intentional xpf semantic).
- Config knobs for the interface-mode port range (fixed 1024-65535);
  registry occupancy/holder introspection (§5.8 follow-up).
- #2387 session-identity enrichment — orthogonal; the colliding flows share
  every context, so #2387 alone would NOT fix this issue.
- DNAT-to-shared-backend / NAT64 / static non-bijective classes — covered
  by the shipped 1:N multimaps; unchanged.
- ALG payload rewriting for PAT'd ports (same posture as pool mode today);
  netflow/syslog translated-port fields (already generic per §4 item 6
  audit).

## 11. Open questions for adversarial review

1. Holder ownership: `Worker(u32) | Shared` with the single
   install+reserve wrapper (§5.6) — is any acquire/release pair still
   unmatched? Walk session_glue/mod.rs:778/1122, commands/upsert_synced.rs,
   ha/session_import.rs, the nine release sites, and the shared-map GC
   paths and name one.
2. Coordinator pre-reserve drop-on-conflict: is dropping a conflicting
   synced import the right fail-closed posture (the flow re-establishes
   post-failover), or must the standby quarantine-and-report instead?
3. §5.7 policy: the POOL loses on overlap (interface addresses are runtime
   reality). Should the interface-mode rule lose instead? Who adjudicates?
4. Exact full-cycle probe (64512 worst case, chunked 64/CS) vs a
   free-index structure (bitmap of per-dst-free candidates): is the chunked
   linear walk acceptable given genuine near-saturation is the only
   expensive case?
5. Registry reclamation cap 256 allocators — right bound, or should it
   derive from the #5877-style aggregate capacity budget?
6. Preserve-first vs Junos-literal always-PAT: Codex r2 notes Juniper
   documents interface NAT as always-PAT; preserve-first is a deliberate
   xpf deviation for wire stability. Does any reviewer demand literal
   parity?
7. Mixed-version window (§5.4): accept, or gate `SessionSyncProtocol`?
8. Is PLAN-KILL (option (c)) defensible for a High security finding given
   the mechanism is now ~verbatim reuse of shipped machinery?
