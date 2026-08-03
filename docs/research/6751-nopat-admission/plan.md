# #6751 plan — interface SNAT no-PAT admission: reserve-or-PAT the colliding translated tuple

- **Status**: DRAFT v1 — pending adversarial plan review
- **Issue**: #6751 (opus-review-001 R08, High, `bug`+`audit`+`security`) —
  interface SNAT admits indistinguishable no-PAT return tuples and sends
  replies to the FIRST session.
- **Base**: `ad9591177481` (origin/master at research start).
- **Scope**: `userspace-dp` Rust dataplane only. No Go control-plane change,
  no wire-format change, no `NatDecision`/`SourceNatLookup` shape change.

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
from that handle: every reply for the ambiguous tuple is un-NAT'd to H1. H2's
return traffic is delivered to H1's host (cross-session data leak), H2 is
blackholed, and H1's stack, seeing segments for a connection it does not own,
emits RSTs that tear down BOTH flows. On the cross-worker shared maps
(`afxdp/shared_ops.rs:897` `publish_shared_session`) the collision is worse:
`shared_nat_sessions` is single-value, so the second publish DISPLACES the
first (counted by `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS`) and which host wins
depends on RSS worker topology — non-deterministic per-flow hijack.

The production test suite PINS the misdelivery:
`session/tests.rs:4560` (`nat_reverse_1n_collision_preserves_displaced_return_path`)
constructs exactly this two-host interface-SNAT collision and at
`session/tests.rs:4602-4610` asserts the reply resolves to the FIRST-installed
session because "the wire tuple is genuinely ambiguous under no-PAT interface
SNAT". The codebase encodes the bug as expected behavior.

The issue is a DESIGN fork, not a one-line bug: what SHOULD interface-mode
SNAT do when two flows would share one translated tuple?

## 2. Honest scope/value framing

This is a correctness/security fix, not a performance change. The absolute
win:

- Eliminates a silent cross-session data leak (one internal host receives
  another host's return traffic — confidentiality/integrity violation on a
  box whose job is traffic separation), plus the RST-injection teardown of
  both flows, plus the non-deterministic shared-map displacement variant.
- Closes a Junos-parity gap: Junos interface-mode SNAT performs port
  translation (PAT) by default — the `security nat source interface
  port-overloading off` knob (in-repo: #4291, accepted-and-advisory) exists
  precisely to tune interface-mode port REUSE, which presupposes interface
  mode PATs. xpf's port-preserving interface mode is the outlier.
- Collision frequency today: requires same protocol + same source port +
  same server + simultaneous liveness. Rare for random-ephemeral TCP, but
  realistic for ICMP echo (Linux ping reuses small per-socket identifiers;
  two hosts pinging one target with the same id is common), for UDP services
  with pinned source ports, and for any middlebox that normalizes source
  ports. It is a deterministic hijack primitive for an insider who can pick
  source ports deliberately (UDP/ICMP: no handshake gate).

If reviewers conclude the fix's churn exceeds the risk (e.g. that the
collision is too rare to justify allocator work, or that a documented
no-PAT semantic is acceptable for a High security finding), PLAN-KILL is an
acceptable verdict — PLAN-KILL here means shipping option (c), status quo
plus documentation, and saying so on the issue.

## 3. What's already shipped / partially batched

Everything the fix needs already exists as a proven pattern in-repo:

| Prior work | What it gives this plan |
|---|---|
| #4399/#4438 1:N multimaps (`nat_reverse_index`, `forward_wire_index`, `reverse_translated_index`) + validate-on-lookup | Retains both colliding handles; stays as defense-in-depth for the OTHER non-bijective classes (DNAT-shared-backend, NAT64, static). |
| **#5269/#5336/#5338/#5341/#6041/#6226** address-only occupancy token (`PortAllocator::reserve_address_only`, `address_only_owners`, `release_flow`/`rollback_flow` address_only arm) | The fail-closed "second collider denied" discipline ALREADY shipped for pool `port no-translation` and port-less protocols — option (b) is a direct application of it. |
| `PortAllocator` lock-free occupancy bitmap (`reserve(port)`, `claim()`, `free_recycle`/`free_no_recycle`) + `live_by_flow` + `max_tracked_flows` | The PAT allocation machinery option (a) reuses verbatim — "existing allocator discipline" per the issue's own fix direction. |
| #4388/#4512 `reserve_synced_source_nat_allocation` (upsert_synced.rs:91) | HA standby reservation pattern the interface registry must mirror. |
| #4074/#4088 ICMP Query Identifier translation (pool mode, RFC 5508 §3.1) | The ICMP-id sub-case of option (a) rides the same rewrite path (`rewrite_src_port` set on an ICMP flow). |
| #1852 non-first-fragment pool-allocation gate + #2562/#5146 forward fragment assoc + #6122 flowless-fragment fail-closed probe | The fragment story for a PAT'd interface flow — decision-driven assoc, read-only probe. |
| #5688 interface-no-egress-address fail-closed | The interface branch already fails closed via `SourceNatLookup::Unavailable` when it cannot translate safely; option (a)/(b) reuse that funnel. |
| `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS` + `nat_reverse_key_collisions` telemetry (#1760 W3') | Existing counters quantify the collision; after the fix they go quiet for the interface class. |
| #4291 `port-overloading off` accepted-with-advisory | Documents that Junos interface-mode overloads ports by default. |
| **OPEN #6522** — sibling replica reap releases a live flow's SNAT allocation (no holder refcount) | Direct adjacency: any new interface-mode allocation registry must NOT reproduce this hazard; see §5.6 and §11. |

## 4. Multiple Path Options (the design fork)

### Option (a) — reserve translated tuple at admission; PAT the later collider (RECOMMENDED)

Interface-mode becomes "pool-mode with a single-address pool whose address is
the resolved egress address, preserve-first":

1. A new NODE-GLOBAL registry, keyed by egress address (NOT per rule — two
   interface-mode rules resolving the same egress address must share one
   registry or cross-rule collisions stay invisible), lives next to
   `source_nat_rules` in `ForwardingState`:
   `interface_nat_allocators: InterfaceNatAllocators` wrapping
   `RwLock<FxHashMap<IpAddr, Arc<PortAllocator>>>`, one
   `PortAllocator::new(1, 1024, 65535)` per egress address (the pool-default
   port range, `compiler_nat_source.go:486-491`), created lazily on first
   admission, carried across commits from `previous` keyed by address
   (mirrors `parse_source_nat_rules_with_previous` /
   `Nat64State::from_snapshots_with_previous` reuse, forwarding_build/mod.rs:312,332).
2. The interface branch of `match_source_nat_result_for_tuple`
   (nat/source.rs:1226) gains the registry + `flow` + `now_ns` (all already
   in scope) and, for a REAL first packet (`non_first_fragment == false`):
   - **port-bearing protocol** (TCP/UDP/ICMP-query per the #4074
     classification): idempotent re-entry check on `live_by_flow[flow]`
     (a racing second packet of the same flow returns its existing
     translation, like `allocate_translation`); else
     `occupancy.reserve(flow.src_port)` —
     - success: decision keeps `rewrite_src_port: None` (port preserved);
       record `live_by_flow[flow] = (egress, src_port)` with the port bit
       claimed. Wire behavior for the 99.99% non-colliding case is
       UNCHANGED.
     - port already owned by a different live flow (or out of range, e.g.
       src port < 1024): `occupancy.claim()` a fresh port and return
       `rewrite_src_port: Some(new_port)` — the later collider is PAT'd,
       its reverse tuple is distinct, and the #4399 bucket goes back to
       len 1 for this flow. Bump a new
       `interface_snat_pat_collisions_total` counter.
     - bitmap full: `SourceNatLookup::Unavailable(AllocatorExhausted)` —
       same fail-closed drop funnel as pool exhaustion (#5688).
   - **port-less protocol** (GRE/ESP/AH/OSPF/HOPOPT, `!has_l4_ports`):
     there is no port to PAT — mint the #5269 address-only reverse-identity
     token (`reserve_address_only(flow, egress)`); a second collider fails
     closed. This is EXACTLY the shipped pool `no-translation` semantics.
3. Release/rollback/reserve symmetry: extend
   `release_source_nat_allocation_with_mode` (nat/source.rs:781) so that when
   no pool rule releases, it consults the registry keyed by
   `nat.rewrite_src` and runs `release_flow`/`rollback_flow` with
   `translated = (rewrite_src, rewrite_src_port.unwrap_or(key.src_port))` —
   the call sites (reap loop_body/mod.rs:1625; 5 rollback sites in
   poll_descriptor/mod.rs; delete_synced.rs:38; promote.rs:194;
   session_glue/mod.rs:563) already fire for interface-mode decisions and
   currently no-op ("a non-pool address translation ... owns no pool
   live_by_flow entry, so the per-rule release is a harmless no-op",
   source.rs:794-799). Extend `reserve_synced_source_nat_allocation`
   (source.rs:834+) the same way: standby reserves the EXACT synced tuple
   via `reserve_flow` (never steals; graceful skip on drift, same as pool).
4. No session-index, lookup, flow-cache, or packet-rewrite changes: once
   translated tuples are unique per flow, the existing bijective fast path
   is correct. NO longer packet-path scan (per the review's guidance).
5. Read-only-probe safety: the #6122 probe
   (`source_nat_would_translate_fragment`) reaches this branch with
   `non_first_fragment = true`; the branch mints NOTHING on that flag and
   returns today's address-only `Matched` — probe stays side-effect-free
   (frag_assoc.rs:281 + nat_exception.rs:96 contract).

Trade-offs: closes the security hole AND the Junos-parity gap; zero
availability loss (colliders PAT, not drop); wire behavior changes ONLY for
flows that are today corrupted. Cost: the registry + release/reserve
extension + the holder discipline in §5.6; the largest diff of the three
options.

### Option (b) — reserve-and-reject: fail the later collider closed

Same registry and release/reserve symmetry as (a), but the port-bearing
branch ONLY does the `reserve(flow.src_port)` step and returns
`Unavailable(AllocatorExhausted)` when it fails — the #5269 pool
address-only discipline applied verbatim to interface mode.

Trade-offs: smallest diff that kills the misdelivery; internally consistent
with pool `no-translation` (#5269); no `rewrite_src_port` on interface mode,
so no ICMP-id/fragment rewrite surface. Cost: the later colliding flow is
DROPPED until the first closes — an availability loss Junos does not have
(it PATs), visible for same-id ICMP ping pairs and pinned-source-port UDP;
keeps xpf's non-Junos no-PAT semantic but makes it fail-closed. The issue's
own framing makes (b) conditional: "reject the later flow atomically **if
interface mode must remain no-PAT**" — and no in-repo doc or Junos semantic
says it must.

### Option (c) — status quo + documentation

Keep the collision; document it in docs/userspace-dataplane-architecture.md
and the gaps table; keep the pinned tests. Trade-offs: zero diff; keeps a
High-severity silent misdelivery + hijack primitive on a security-labeled
issue. Presented for completeness; recommended AGAINST.

**Recommendation: option (a)**, preserve-first + PAT-later-collider, with the
port-less fail-closed token. It is the issue's primary fix direction, it is
what Junos does, it loses no availability, and every mechanism it needs is
already proven in-tree. Option (b) is the retreat if review judges (a)'s
diff too large for the risk.

## 5. Concrete design

### 5.1 Registry type (new, `userspace-dp/src/nat/`)

```rust
/// Node-global interface-mode SNAT allocation registry. ONE allocator per
/// egress address, shared by every interface-mode rule (a per-rule registry
/// would miss cross-rule collisions on the same egress address). Keyed by
/// the RESOLVED egress address (the `rewrite_src`), so a zone-scoped
/// rule-set egressing multiple interfaces is handled per address.
pub(crate) struct InterfaceNatAllocators {
    map: RwLock<FxHashMap<IpAddr, Arc<PortAllocator>>>, // 1-address, 1024-65535
    // holder discipline per §5.6 lives inside the per-flow record.
}
impl InterfaceNatAllocators {
    fn allocator_for(&self, egress: IpAddr) -> Arc<PortAllocator>; // lazy-create
    fn release(&self, flow: SourceNatFlowKey, translated: TranslatedTuple, rollback: bool);
    fn reserve_synced(&self, flow: SourceNatFlowKey, translated: TranslatedTuple);
    /// carried across forwarding rebuilds keyed by address (allocator state
    /// survives commits that keep the egress address; mirrors
    /// previous_allocators / nat64 reuse in forwarding_build/mod.rs).
    fn carry_over(prev: &Self, live_egress: &FastSet<IpAddr>) -> Self;
}
```

`ForwardingState` gains `interface_nat_allocators: InterfaceNatAllocators`
(types/forwarding.rs:34); `forwarding_build/mod.rs` populates it via
`carry_over(previous, current-egress-address-set)` next to the
`parse_source_nat_rules_with_previous` call (mod.rs:312).

### 5.2 Admission mint (nat/source.rs:1226 interface branch)

Signature ripple (all `pub(crate)`): `match_source_nat_result_for_tuple`
gains `iface_allocs: &InterfaceNatAllocators`; threaded through
`match_source_nat_for_flow_result_at` (afxdp/forwarding/nat.rs:104),
`source_nat_decision_for_flow` (poll_descriptor/nat_exception.rs:24), the
#6122 probe (nat_exception.rs:96), and the coordinator test helper
(coordinator/status.rs:556). The interface branch becomes:

```rust
if rule.interface_mode {
    let Some(rewrite_src) = (egress addr of the packet's family) else {
        return Unavailable(InterfaceNoEgressAddress);   // #5688, unchanged
    };
    if non_first_fragment {
        return Matched(address-only decision);           // read-only probe path, unchanged
    }
    let alloc = iface_allocs.allocator_for(rewrite_src);
    if port_less {                                        // GRE/ESP/HOPOPT...
        return match alloc.reserve_address_only(flow, rewrite_src) {
            Ok(_)  => Matched(address-only decision),     // token minted
            Err(r) => Unavailable(for_rule(rule, r)),     // second collider: fail closed
        };
    }
    // port-bearing (TCP/UDP/ICMP-query):
    //   idempotent re-entry -> existing translation;
    //   else reserve(orig) -> Matched { rewrite_src, rewrite_src_port: None }
    //   else claim()       -> Matched { rewrite_src, rewrite_src_port: Some(p) }
    //   else               -> Unavailable(AllocatorExhausted)
}
```

A tiny helper on `PortAllocator` (`allocate_interface(flow, src_port)`)
packages the idempotent/reserve/claim sequence so the reserve→claim
transition is one critical section (no TOCTOU between the two probes —
mirrors how `allocate_translation` holds `live` across check+insert).

### 5.3 Release / rollback / reserve-synced

`release_source_nat_allocation_with_mode` (source.rs:781): after the pool
rule loop finds no release, consult
`iface_allocs.release(flow, (rewrite_src, rewrite_src_port.unwrap_or(key.src_port)), rollback)`.
`reserve_synced_source_nat_allocation`: after the pool arm, consult
`iface_allocs.reserve_synced(flow, (rewrite_src, port))` → per-address
`reserve_flow` (never steals; false = graceful skip, logged at Debug).
Both gain the `iface_allocs` parameter; all seven call sites already pass
`forwarding` (they gain one field access each).

### 5.4 HA / mixed-version

Synced decisions carry `rewrite_src_port` over the existing wire — a PAT'd
interface flow needs no wire change. Standby reserves the exact tuple;
post-failover local admissions cannot re-claim it. Mixed-version
(new standby + old active): the old active can still admit a colliding pair;
the standby reserves the first, skips the second (graceful), and the pair
stays broken exactly as it was on the active — transitional, self-healing on
session reap. New + new clusters never admit the pair.

### 5.5 Fragments / ICMP

- First fragment carries L4 → normal admission; the forward fragment assoc
  (#2562/#5146) stores the decision (with any PAT port) and non-first
  fragments consult it — the same decision-driven path pool PAT uses today.
- Out-of-order non-first-first fragments: dropped fail-closed by the #6122
  probe, unchanged; the probe stays read-only per §5.2.
- ICMP echo under interface mode: the identifier rides `src_port`; a
  colliding same-id pair gets the second id translated through the SAME
  `rewrite_src_port` machinery as pool-mode #4074 (RFC 5508 §3.1), including
  the incremental checksum repair.

### 5.6 The #6522 holder discipline (mandatory, not optional)

`reap_expired_sessions` (loop_body/mod.rs:1625) releases unconditionally for
every expired entry, and sibling `WorkerLocalImport` replicas age out
independently — that is the OPEN #6522 pool bug. The interface registry
must not reproduce it: the per-flow record carries a node-local
`holders: u32` —
`+1` at local admission mint, `+1` at sibling UpsertSynced install
(new reserve call in the `!is_peer_synced` arm of upsert_synced.rs, mirroring
the peer-synced arm at :91), `+1` at peer-synced reserve; `-1` at every
release site (reap / delete-sync / promote / demote / rollback); the port
bit / token frees only at zero. Sibling-replica reaps then decrement a
holder they incremented, and the owner's tuple stays reserved while ANY
replica lives. The pool allocator's equivalent fix remains #6522's own
issue — explicitly out of scope here — but the registry's holder record is
shaped so #6522 can adopt the same pattern. Reviewers: if you judge the
holder counter scope creep, the fallback is an origin-gated release (skip
release when the reaped entry never reserved); say which you demand.

## 6. Public API preservation

Preserved byte-for-byte (frozen shapes the codebase treats as wire-/Eq-
contract): `NatDecision`, `SourceNatLookup`, `SessionKey`,
`SyncedSessionEntry`, the HA session-sync wire, the Go→helper snapshot
protocol (`SourceNATRuleSnapshot` gains NO fields), all CLI/gRPC surfaces.
Changed signatures are `pub(crate)`-internal only:
`match_source_nat_result_for_tuple` (+1 arg),
`match_source_nat_for_flow_result_at` (+1),
`source_nat_decision_for_flow` (+1),
`source_nat_would_translate_fragment` (+1),
`release_source_nat_allocation` / `rollback_source_nat_allocation` /
`reserve_synced_source_nat_allocation` (+1 each),
plus the coordinator test helper. No behavioral change to pool/static/NPTv6/
NAT64/DNAT paths; the #1377 two-fail-closed-site contract guard keeps its
call-site count (the probe wraps the same helper).

## 7. Hidden invariants the change must preserve

- **Probe purity**: `non_first_fragment == true` mints NOTHING (#6122
  read-only contract; nat_exception.rs:96 "Side-effect-free").
- **Idempotent re-entry**: a racing second packet of the same flow returns
  the existing translation; no double-claim, no port churn mid-install
  (allocator.rs:1036 precedent).
- **Release symmetry**: every mint is freed by exactly the existing teardown
  sites — no new delete site (the #4388/#5269 doctrine). Rollback frees
  WITHOUT recycle/accounting differences the pool path encodes in
  `rollback_flow` vs `release_flow` (allocator.rs:1392).
- **Never-steal**: `reserve` fails rather than evict a different flow's live
  port (reserve_flow allocator.rs:1679); the standby synced-reserve skips
  gracefully on drift.
- **Cross-worker atomicity**: reserve→claim and check→insert run inside one
  `live` mutex critical section; the bitmap claim is lock-free CAS; no
  per-packet locking is added (admission-only, cold path).
- **Commit carry-over**: allocator state survives a forwarding rebuild that
  keeps the egress address (previous-state reuse keyed by address — the
  #4518 nat64 precedent); an address REMOVED by a commit drops its allocator
  with the old state (no new flow can resolve to it).
- **NatDecision freeze**: no new fields; `rewrite_src_port: Some(_)` on an
  interface-mode decision is the only new observable state, and every
  consumer (checksum rewrite, fragment assoc, HA sync, flow-cache seed)
  already handles that shape from pool mode.
- **Hot path**: established-flow transit (`stage_flow_cache_hit`) untouched;
  zero new per-packet work; the 1:N multimaps stay len-1 inline SmallVec for
  interface SNAT after the fix.
- **Logging**: no `slog`/eprintln per admission; PAT-collision and
  exhaustion ride existing counters + the NAT failure event path
  (`record_source_nat_failure`), and the new PAT counter is polled, not
  pushed.

## 8. Risk assessment

| Class | Rating | Notes |
|---|---|---|
| Behavioral regression | MED | Wire change only for flows that are corrupted today (later collider PAT'd). Preserve-first keeps all non-colliding flows byte-identical. The pinned tests at session/tests.rs:4560/4602 still pass (they install decisions directly, bypassing admission) but their comments go stale and must be re-pointed at the residual collision classes. Fragment/ICMP paths deliberately reuse pool-mode machinery. |
| Lifetime / borrow-checker | LOW | Registry is `Arc<PortAllocator>` clones out of an `RwLock`; no borrows escape; matches `wg_engines`/`nat64` sharing shape. |
| Performance regression | LOW | Admission-only `RwLock` read (hit) or write (first use per address); one bitmap CAS + one tiny mutex per NEW interface-mode flow; zero per-packet cost; #919/#5445 hot-path-atomic doctrine intact (no new per-packet atomics). |
| Architectural mismatch | LOW | Reuses the existing allocator discipline the issue itself names; no new subsystem, no packet-path scan (explicitly guided away from), no second source of truth for NAT state (registry is the allocator, sessions stay the authority for delivery). |

## 9. Test plan

- `cargo build` clean; full `make test-rust` (userspace-dp suite) and
  `make test-go`; `make test` umbrella. Fleet cap: build with
  `CARGO_TARGET_DIR=/home/ps/cargo-target/research-6751`.
- New unit tests (nat/source.rs + allocator):
  preserve-first success (port kept, bit claimed, release frees and a later
  flow re-preserves); collision → PAT (distinct translated ports, distinct
  `reverse_wire_key`s, both flows' replies resolve to their OWN forward
  session via `find_forward_nat_match`); out-of-range source port (<1024)
  → immediate PAT; bitmap exhaustion → `Unavailable(AllocatorExhausted)`;
  idempotent re-entry (same flow twice, same tuple, one claim);
  port-less GRE → token minted, second collider fail-closed;
  ICMP same-id pair → second id translated (RFC 5508);
  cross-rule same-egress collision detected (two rules, one registry);
  probe read-only (non_first_fragment=true mints nothing);
  rollback frees (admission abort → port reusable);
  reserve_synced mirrors active (standby cannot re-claim the synced tuple);
  holder refcount (sibling replica reap does not free the owner's tuple —
  RED on the #6522 shape).
- Existing pins: session/tests.rs:4560/4602 stay GREEN (multimap machinery
  untouched) with updated comments; the #4399/#4438 suites unchanged;
  #5269/#5336 token suites unchanged (pool path untouched).
- Go: `make test-go` (no Go change expected; run to prove the snapshot
  contract is untouched).
- Smoke (loss userspace cluster, lock protocol per CLAUDE.md): two test
  hosts behind interface-mode SNAT, same source port to the same iperf3/
  netcat target — both flows establish, distinct external ports observed on
  the WAN side (tcpdump), replies land on the correct host; same-id ping
  pair to one target both get replies; `make test-failover` (HA reserve
  adjacency).
- Counters: `interface_snat_pat_collisions_total` bumps exactly on
  collision; `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS` stays flat for the
  interface class.
- Docs sweep: docs/userspace-dataplane-architecture.md (interface-mode
  bullet + the #4399 1:N section's collision-class list),
  docs/userspace-dataplane-gaps.md:44 row, `_Log.md`.

## 10. Out of scope (explicitly)

- Pool allocator holder refcount (#6522) — open sibling issue; the interface
  registry ships with holders from day one, pool keeps its known exposure
  until #6522 lands.
- Cross-destination port overloading (Junos `port-overloading` ON semantics
  — reuse one translated port across DIFFERENT servers). Strict
  per-(egress,port) claim is simpler and safer; capacity 64512/egress.
- Junos-literal always-PAT (translate every interface-mode flow's port even
  without a collision) — larger wire change, no correctness gain.
- Config knobs for the interface-mode port range (fixed 1024-65535, the
  pool default); Go compiler/schema changes.
- #2387 session-identity enrichment (zone/VRF in the key) — orthogonal;
  the colliding flows here share every context, so #2387 would NOT fix this
  issue.
- DNAT-to-shared-backend / NAT64 / static non-bijective classes — already
  covered by the shipped 1:N multimaps; unchanged.
- The reverse `interface_nat_v4/v6` local-delivery maps — untouched.

## 11. Open questions for adversarial review

1. Is the NODE-GLOBAL per-egress-address registry the right key, or is
   there a cross-context case (same egress address in two VRFs via
   overlapping config) where keying by address alone wrongly shares or
   wrongly splits the reservation namespace? Should the key be
   (egress address, routing-instance)?
2. Holder refcount vs origin-gated release for the #6522-shaped replica
   hazard (§5.6): is the refcount scope justified in THIS PR, or should the
   registry ship origin-gated and adopt #6522's eventual mechanism?
3. Preserve-first vs Junos-literal always-PAT: does any reviewer hold that
   port preservation is itself the parity violation (Junos allocates, it
   does not preserve), and that (a) should allocate on EVERY interface-mode
   admission? What breaks operationally if we do?
4. Is `reserve_address_only`'s (protocol, egress, 0, dst, dst_port) identity
   for port-less protocols the right strictness for interface mode, or
   should the port-less token drop the remote endpoint (strict
   per-(proto,egress) — much lower capacity but matches the bitmap model)?
5. Does threading `iface_allocs` through `match_source_nat_result_for_tuple`
   (mint inside the matcher, like pool mode) versus post-processing in
   `source_nat_decision_for_flow` (mint outside, needs an interface-matched
   signal on a frozen type) have a hidden third option the plan missed?
6. Mixed-version HA (new standby + old active): is the transitional
   skip-and-stay-broken story acceptable, or must the reserve-synced path do
   something stronger (e.g. refuse the sync)? What does the #1961
   additive-wire doctrine demand here?
7. Should `interface_snat_pat_collisions_total` be per-address (cardinality
   risk if an attacker churns egress addresses? — addresses are config-bound,
   so bounded) or one global counter?
8. Is PLAN-KILL (option (c), document the no-PAT semantics) defensible for a
   High security finding given the fix reuses proven machinery? If yes,
   under what risk calculus?
