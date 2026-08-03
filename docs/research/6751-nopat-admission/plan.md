# #6751 plan — interface SNAT no-PAT admission: reserve-or-PAT the colliding translated tuple

- **Status**: DRAFT v2 — round-1 fold (Claude SMR B1-B4/M5-M8/N9-N10, Codex
  r1 blockers 1-4 + majors 5-9 + minors 10-12, AGY r1 blockers 1-2 +
  major 3-4 + minor 5-6 + nit 7 all folded)
- **Issue**: #6751 (opus-review-001 R08, High, `bug`+`audit`+`security`) —
  interface SNAT admits indistinguishable no-PAT return tuples and sends
  replies to the FIRST session.
- **Base**: `ad9591177481` (origin/master at research start).
- **Scope**: `userspace-dp` Rust dataplane + one contained Go validator
  extension (§5.7). No wire-format change, no `NatDecision`/
  `SourceNatLookup` shape change, no control-status/API addition.

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
smoke test will demonstrate it — reworded per Codex r1 minor 12). On the
cross-worker shared maps (`afxdp/shared_ops.rs:897` `publish_shared_session`)
the collision is worse: `shared_nat_sessions` is single-value, so the second
publish DISPLACES the first (counted by
`NAT_REVERSE_KEY_SHARED_DISPLACEMENTS`) and which host wins depends on RSS
worker topology — non-deterministic per-flow hijack. No packet field can
disambiguate after admission: the reply `(S:80 -> E:5555)` carries zero
identifying header fields, and no index (SessionKey/NatDecision/metadata)
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
- Narrows a Junos-parity gap: Junos interface-mode source NAT performs port
  translation — the Junos grammar carries `security nat source interface
  port-overloading off` to tune interface-mode port REUSE (in-repo: #4291
  records the knob accepted-and-advisory at
  pkg/config/compiler_nat_source.go:253-271), which presupposes interface
  mode translates ports. xpf's port-preserving interface mode is the
  outlier. The evidence supports "Junos translates ports in interface
  mode"; it does NOT prove Junos preserves-when-free (it does not), and §4
  presents preserve-first as an intentional xpf semantic, not claimed
  literal parity (reworded per Codex r1 major 7 / AGY r1 minor 5).
- Collision frequency today: requires same protocol + same source port +
  same server + simultaneous liveness. Rare for random-ephemeral TCP, but
  realistic for ICMP echo (Linux ping reuses small per-socket identifiers;
  two hosts pinging one target with the same id is common), for UDP services
  with pinned source ports, and for any middlebox that normalizes source
  ports. It is also a deterministic insider primitive: a malicious internal
  host can deliberately squat a victim's (port, server) external identity
  (UDP/ICMP need no handshake).

If reviewers conclude the fix's churn exceeds the risk, PLAN-KILL is an
acceptable verdict — PLAN-KILL here means shipping option (c), status quo
plus documentation, and saying so on the issue.

## 3. What's already shipped / partially batched

| Prior work | What it gives this plan |
|---|---|
| #4399/#4438 1:N multimaps + validate-on-lookup | Retains both colliding handles; stays as defense-in-depth for the OTHER non-bijective classes (DNAT-shared-backend, NAT64, static). |
| **#5269/#5336/#5338/#5341/#6041/#6226** address-only occupancy token (`PortAllocator::reserve_address_only`, `address_only_owners`, `release_flow`/`rollback_flow` address_only arm) | THE mechanism v2's option (a) is built on: identity-keyed occupancy `(protocol, translated_ip, translated_port, dst_ip, dst_port)`, single-mutex mint (no TOCTOU), idempotent re-entry, fail-closed collision. Preserve AND PAT both mint this token shape, so release/rollback are verbatim reuse. |
| #5144 strict overlap validator (`pkg/config/compiler_validate_strict_nat.go:2525-2576`, owners = source pools + NAT64 pools) | The commit-time pattern §5.7 extends to interface-mode egress addresses: reject independently-owned overlap so disjoint allocator domains can never mint one tuple. |
| #4388/#4512 `reserve_synced_source_nat_allocation` (upsert_synced.rs:91) | HA standby reservation pattern (never-steal, graceful skip) the interface registry mirrors. |
| #4074/#4088 ICMP Query Identifier translation (pool mode, RFC 5508 §3.1) | The ICMP-id sub-case rides the same `rewrite_src_port` rewrite + checksum path. |
| #1852 fragment gate + #2562/#5146 forward fragment assoc + #6122 flowless-fragment fail-closed probe | The fragment story: decision-driven assoc for PAT'd flows, read-only probe preserved. |
| #5688 interface-no-egress-address fail-closed | The `Unavailable` funnel option (a)/(b) reuse on exhaustion. |
| `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS` + `nat_reverse_key_collisions` (#1760 W3') | The collision tripwires; after the fix they go quiet for the interface class. |
| Session-limit count discipline (`session_limit_inc` at install.rs:232/446/580; `session_limit_dec` in the sole removal sink `remove_entry`) | The lifecycle-truth precedent §5.6's holder model follows: counted at the real entry-install sites, decremented at the sole removal sink, origin-agnostic, replay-safe. |
| **OPEN #6522** — sibling replica reap releases a live flow's SNAT allocation | The new registry's holder model (§5.6) is designed so this hazard cannot exist in it; pool-side fix remains #6522's own issue. |

## 4. Multiple Path Options (the design fork)

### Option (a) — reserve translated identity at admission; PAT the later collider (RECOMMENDED)

Interface-mode becomes "address-only occupancy with preserve-first and a
bounded PAT probe on collision", built ENTIRELY on the shipped #5269 token
machinery:

1. **Registry (node-lifetime, OUTSIDE ForwardingState)** — round-1 Codex
   blocker 2 / AGY blocker 2 / SMR B2: v1's `carry_over` inside the
   ArcSwap'd ForwardingState had two fatal generation hazards (lazy-create
   in old vs new generation minting two allocators for one address;
   remove/re-add dropping live reservations). v2 places the registry where
   the shared session maps already live: created once at helper start,
   threaded through the worker context exactly like `shared_sessions` /
   `shared_nat_sessions`, NEVER rebuilt on commit. One
   `Arc<PortAllocator>` per egress address, lazily created, never dropped
   (distinct-address count is config-bounded). A removed address's
   allocator simply receives no new mints (egress resolution reads the new
   forwarding map) while old sessions release into it normally — no
   tombstones, no ABA, no cross-generation aliasing.
2. **Occupancy model (identity-set, no bitmap claims)** — round-1 Codex
   major 6: v1's strict per-(addr,port) bitmap PAT'd flows that are NOT
   ambiguous on the wire (same port to different servers; TCP vs UDP same
   numeric port; every source port < 1024), contradicting the "wire changes
   only for corrupted flows" claim and imposing the Junos
   port-overloading-OFF posture by stealth. v2 instead keys occupancy on the
   FULL reverse identity `(protocol, egress_addr, port, dst_ip, dst_port)`
   — exactly the shipped `AddressOnlyReverseKey`
   (`nat/allocator.rs:178-183`). Consequences:
   - same source port to different servers: distinct identities → BOTH
     preserve (wire change only for genuinely ambiguous pairs — the claim
     restored);
   - TCP vs UDP same numeric port: protocol is in the key → both preserve;
   - source port < 1024 (incl. small ICMP ids): identity map is not
     range-bounded → preserved; only PAT candidates are drawn ≥ 1024;
   - cross-destination port reuse is allowed — the Junos-default
     OVERLOADING posture, not the off posture.
3. **Admission mint** (interface branch, nat/source.rs:1226): gated
   `!non_first_fragment && !tuple_unknown` (round-1 SMR B1 / Codex major 5:
   the synthetic address-only wrapper passes `protocol: None` →
   `tuple_unknown`; the #6122 fragment probe passes
   `non_first_fragment = true`; BOTH probe classes must mint nothing and
   return today's address-only `Matched`):
   - **port-less protocol** (GRE/ESP/AH/OSPF/HOPOPT):
     `alloc.reserve_address_only(flow, egress)` — Ok → Matched
     (address-only); Err → `Unavailable(AllocatorExhausted)` fail-closed
     (verbatim #5269 semantics).
   - **port-bearing** (TCP/UDP/ICMP-query): ONE mutex critical section —
     (i) idempotent re-entry: `live_by_flow[flow]` hit returns the existing
     translation (a racing second packet of the same flow; note RSS/flow-
     hash steering pins one flow's packets to one worker, so cross-worker
     same-flow races do not occur in the AF_XDP model — the idempotent path
     covers worker-reconfig and HA replays); (ii) identity-mint the
     PRESERVED tuple `(proto, egress, flow.src_port, dst, dst_port)` —
     success → Matched with `rewrite_src_port: None` (port preserved, no
     wire change); (iii) identity already held by a different flow → PAT
     probe: draw candidates from the allocator's atomic round-robin cursor
     (`try_next_port` over 1024-65535) and identity-mint
     `(proto, egress, candidate, dst, dst_port)`; first success → Matched
     with `rewrite_src_port: Some(candidate)`; probe budget 4096 →
     `Unavailable(AllocatorExhausted)` (statistically exhaustive: a
     (dst,port) pair holding D of 64512 identities fails 4096 probes with
     probability (D/64512)^4096 ≈ 0 unless D ≈ 64512, i.e. genuine
     exhaustion).
   - The preserved and PAT'd tokens are the SAME `address_only` record
     shape in the SAME `address_only_owners` map with `live_by_flow[flow]
     = (egress, port)`, `address_only: true` — so the SHIPPED
     `release_flow`/`rollback_flow` address_only arm frees either verbatim
     (`nat/allocator.rs:1332-1345`, `:1404-1418`). No bitmap bit is ever
     claimed for interface mode; the atomic cursor's natural wrap gives the
     reuse hysteresis the #3011 recycle ring gives pools. No
     reserve-then-claim two-step exists, so the AGY r1 blocker-1 / SMR M5
     race (spurious PAT + bitmap churn from a lock-free reserve racing the
     map insert) CANNOT occur: the mint is one mutex'd check+insert.
4. **Capacity**: per-address allocator
   `PortAllocator::new(1, 1024, 65535)` → `max_tracked_flows` 64512
   (`allocator_capacity`), enforced by the existing `live_by_flow.len()`
   check inside `reserve_address_only`; port-less and PAT'd tokens consume
   the same cap (documented per Codex r1 major 6). Sync-import reserve
   mirrors the pool #4388 posture and does NOT cap (HA fidelity —
   documented policy choice, per Codex r1 major 6's `reserve_flow`
   observation).
5. **Release/rollback/reserve symmetry**: the NINE production release sites
   (round-1 Codex minor 10 corrected the count): reap
   `loop_body/mod.rs:1625`; five admission-abort rollbacks
   `poll_descriptor/mod.rs:2313/2374/2472/2634/4902`; synced delete
   `session_glue/commands/delete_synced.rs:38`; translated-sync purge
   `session_glue/promote.rs:194`; terminal teardown
   `session_glue/mod.rs:563`. All call
   `release_source_nat_allocation_with_mode` (nat/source.rs:781), which v2
   extends: after the pool-rule loop releases nothing, consult the registry
   keyed by `nat.rewrite_src` and run the same
   `release_flow`/`rollback_flow` with
   `translated = (rewrite_src, rewrite_src_port.unwrap_or(key.src_port))`.
   Discrimination is FLOW-keyed (round-1 SMR M6): `release_flow` matches
   `live_by_flow[flow]` AND `existing.translated == translated`
   (`allocator.rs:1318-1330`), so a pool address-only decision and an
   interface-mode decision — byte-identical at release time — each miss the
   other's registry. The dormant RST-teardown path
   (`session_glue/mod.rs:908`, unreachable while
   `should_teardown_tcp_rst` returns false at :893) is explicitly EXCLUDED
   from the invariant (Codex r1 minor 10). `reserve_synced_source_nat_allocation`
   (nat/source.rs:834+) gains the identical interface arm: standby mints the
   EXACT synced identity (never steals; conflict → graceful skip, the #4388
   posture — see §5.6 for the accepted-scope discussion).
6. **No session-index, lookup, flow-cache, or packet-rewrite changes**: once
   translated identities are unique per flow, the existing bijective fast
   path is correct. NO longer packet-path scan (per the review's guidance).
   Surface audit (round-1 AGY minor 6 / Codex major 8, resolved POSITIVE):
   `rewrite_src_port: Some(_)` is already handled generically on every
   downstream surface from pool mode — flow-cache descriptor copy
   (`flow_cache.rs:586`), conntrack publish (`publish_conntrack.rs:197`),
   gRPC session render (`server_sessions.go:1724`), RT_FLOW event records
   (`rt_flow.rs:82`), HA conversion (`daemon_ha_userspace_convert.go:357`
   carries `NATSrcPort`). No new fields anywhere.

Trade-offs: closes the security hole AND the availability hole (later
collider PATs, never drops); wire behavior changes ONLY for flows that are
ambiguous on the wire today; (b)'s identity-squatting DoS (below) is avoided
because the victim PATs around the squatter. Cost: the registry + holder
model + the §5.7 validator extension.

### Option (b) — reserve-and-reject: fail the later collider closed

Identical machinery minus the PAT probe: the identity-mint Err maps straight
to `Unavailable(AllocatorExhausted)`.

Trade-offs: smallest possible diff (a strict subset of (a)'s); internally
consistent with pool `no-translation` (#5269). Cost: (i) availability loss
Junos does not have — the same-id ICMP ping pair hard-fails the second host;
(ii) **identity-squatting DoS**: an insider who learns a victim's
(source port, server) pair — or brute-forces the 64k space against a known
victim server — mints the identity first and keeps re-opening it; the
victim's flow is denied every time until the squatter stops. (b) converts a
confidentiality bug into an availability bug under the SAME attacker
preconditions. Under (a) the victim PATs around the squatter and keeps
service. (Round-1 AGY major 4 argued (b) is the defensible choice for a
High security issue; this DoS vector is the counter-argument, and v2's
redesign removes AGY's stated basis — "high-risk architectural churn" — by
making (a) ≈ (b) + one bounded probe loop over the same mutex'd mint.)

### Option (c) — status quo + documentation

Keep the collision; document it; keep the pinned tests. Zero diff; keeps a
High-severity silent misdelivery + hijack/squat primitive on a
security-labeled issue. Presented for completeness; recommended AGAINST.

**Recommendation: option (a)** — preserve-first identity reservation +
bounded PAT probe + port-less fail-closed token + §5.7 overlap rejection.
(b) is the documented retreat if review judges the probe loop unacceptable.

## 5. Concrete design

### 5.1 Registry type and placement

```rust
/// Node-lifetime interface-mode SNAT identity registry. ONE allocator per
/// egress address, shared by every interface-mode rule (a per-rule registry
/// would miss cross-rule collisions on the same egress address) and keyed
/// by ADDRESS ONLY (round-1 Codex minor 11 / SMR M8: the reverse lookup
/// namespace is global-by-address — SessionKey carries no VRF/zone/ifindex
/// (session/key.rs:9) and #2387 is open — so the allocator must be at least
/// as coarse as the lookup key; (address, VRF) keying would let two VRF
/// allocators emit one globally-indexed tuple). Lives OUTSIDE
/// ForwardingState (next to shared_sessions/shared_nat_sessions in the
/// worker context): created once at helper start, never rebuilt on commit.
pub(crate) struct InterfaceNatAllocators {
    map: RwLock<FxHashMap<IpAddr, Arc<PortAllocator>>>, // 1-address each, 1024-65535
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
(coordinator/status.rs:556). The production caller inventory is those two
sites plus the address-only wrapper (nat/source.rs:1109); the #1377
"exactly two fail-closed decision sites" textual guard
(userspace-dp/tests/snat_contract_doc_guard.rs:53) counts decision SITES,
not signatures — unchanged (verified per Codex r1 major 5). The interface
branch:

```rust
if rule.interface_mode {
    let Some(rewrite_src) = (egress addr of the packet's family) else {
        return Unavailable(InterfaceNoEgressAddress);        // #5688, unchanged
    };
    if non_first_fragment || tuple_unknown {
        return Matched(address-only decision);   // BOTH probe classes: mint nothing
    }
    let alloc = iface_allocs.allocator_for(rewrite_src);     // lazy-create, registry-lifetime
    if port_less {
        return match alloc.reserve_address_only(flow, rewrite_src) {
            Ok(_)  => Matched(address-only decision),
            Err(r) => Unavailable(for_rule(rule, r)),         // second collider: fail closed
        };
    }
    match alloc.allocate_interface_identity(flow, rewrite_src, now_ns) {
        // one live-mutex CS: idempotent re-entry -> existing; else mint preserved
        // identity (proto, egress, src_port, dst, dst_port); on identity conflict
        // probe <= 4096 cursor candidates minting (proto, egress, cand, dst, dst_port);
        // success Some(p)==src_port -> rewrite_src_port None (preserved),
        // Some(p)!=src_port -> Some(p) (PAT'd); budget out -> Unavailable(AllocatorExhausted)
    }
}
```

### 5.3 Release / rollback / reserve-synced

`release_source_nat_allocation_with_mode` and
`reserve_synced_source_nat_allocation` each gain the `iface_allocs`
parameter (the nine release sites + the one reserve site already sit where
the worker context reaches). Pool loop first (unchanged), interface arm
second, flow-keyed discrimination per §4 item 5. Synced reserve mints the
exact synced identity (`translated.port = rewrite_src_port.unwrap_or(key.src_port)`);
conflict → graceful skip (Debug log), the #4388 never-steal posture.

### 5.4 HA / mixed-version

Synced decisions carry `rewrite_src_port` over the existing wire — no wire
change. Mixed-version rolling upgrade (round-1 Codex major 8 / AGY major 3):
- new active → old standby: the old standby IMPORTS the PAT'd decision fine
  (the field is generic — `daemon_ha_userspace_convert.go:357` carries it
  for pool flows today; AGY r1's "mis-parse / fail to install" claim was
  checked against the conversion + install path and does not hold: nothing
  in the old code asserts `rewrite_src_port == None` for interface-mode
  decisions). The old standby never RESERVES it (its reserve skips non-pool
  rules, nat/source.rs:921). Post-failover it can admit a no-PAT flow onto
  the synced tuple — collision probability equal to the pre-existing bug's,
  not worse.
- old active → new standby: the pair the old active admitted collides on
  the standby exactly as it did on the active; the new standby reserves the
  first, skips the second (graceful). AGY r1's "second flow un-tracked"
  overstates it: the second flow's session is installed and forwards; its
  reverse identity is simply not reserved, same as pre-fix.
- Verdict: an ACCEPTED, documented rolling-upgrade window bounded by the
  pre-existing bug's probability, closing when both nodes upgrade.
  `SessionSyncProtocol` gating (pkg/upgrade/imageversions.go:162) was
  considered and rejected: hard-gating breaks HA session sync during any
  rolling upgrade — worse than the window. Reviewers may overrule.

### 5.5 Fragments / ICMP

Unchanged from v1 and verified against the machinery: first fragment carries
L4 → normal admission; the forward fragment assoc (#2562/#5146) stores the
decision (with any PAT port) and non-first fragments consult it (the same
decision-driven path pool PAT uses); out-of-order non-first-first fragments
drop fail-closed via the #6122 probe (unchanged, probe purity per §5.2);
ICMP echo id collision → second id translated through the #4074
`rewrite_src_port` machinery (RFC 5508 §3.1) including incremental checksum.

### 5.6 Holder model (round-1 Codex blocker 3 / SMR B3 — redesigned)

v1's scalar refcount desynced on sync-refresh replays, origin-boolean
ambiguity (`is_peer_synced()` spans SyncImport | SharedMaterialize |
WorkerLocalImport, session/entry.rs:242-246), bypass install paths
(`WorkerCommand::UpsertLocal` at session_glue/mod.rs:778, shared-map
materialization at :1122), and count-neutral promote/demote (promote.rs:99
mutate-in-place; install.rs:568 demote-flip). v2 replaces it with a
**per-worker holder SET** on the allocation record:

- `holders: FxHashSet<u16>` (worker/binding index) on the flow's
  `live_by_flow` record (or a sibling map — implementation detail).
- `+{W}` at local admission mint (W = admitting worker); `+{W}` at sync
  reserve (W = importing worker — every entry import passes
  upsert_synced.rs:91 exactly once per worker per entry; replays/replaces
  re-call reserve but the set ALREADY contains W → no-op → no leak on
  replay, no replace imbalance).
- `−{W}` at every release/rollback site (each runs on a worker; the worker
  id threads through with the registry param). Free the identity when the
  set empties.
- Promote / demote / materialize / #1752 in-place refresh make NO
  reserve/release calls → neutral by construction.
- Net effect: the identity survives while ANY entry replica lives
  node-wide — the #6522 hazard (sibling replica reap freeing the owner's
  tuple) cannot exist in this registry. Pool-mode's equivalent fix remains
  #6522's own issue; this model is shaped so #6522 can adopt it.
- Saturating-decrement rule: a `−{W}` for an absent holder Debug-logs and
  clamps; release stays flow+tuple-keyed so a stray decrement can never
  touch a different flow's allocation.

Round-1 Codex blocker 4 (import is install-then-reserve, so a reserve
conflict leaves a live unreserved imported entry): v2 keeps the #4388
never-steal graceful-skip posture — the same accepted drift window pool
mode has shipped since #4388, with `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS`
as the tripwire. Transactional reserve-before-install / quarantine was
considered and deferred as scope creep touching the synced-install fast
path; reviewers may demand it.

### 5.7 Cross-domain overlap rejection (round-1 Codex blocker 1 / SMR B4)

The interface registry, source-pool allocators, and NAT64 allocators are
DISJOINT occupancy domains; a source pool (or NAT64 pool) containing the
egress interface's own address E reintroduces the collision across the
seam. Extend the #5144 strict validator
(`pkg/config/compiler_validate_strict_nat.go:2525-2576`,
`natAllocOwner`/`validateNATPoolExternalTupleOverlapStrict`) to enumerate
interface-mode egress addresses as owners — one owner per interface-mode
rule, pool = the resolved interface addresses of its egress context
(zone/interface/routing-instance). Overlap → REJECT at strict commit; WARN
on tolerant load / peer-sync (the #5837/#1960 no-brick two-posture
doctrine; a previously-committed overlapping config must not brick boot).
With the overlap illegal, each translated address belongs to exactly ONE
domain, which ALSO resolves the HA reserve provenance ambiguity Codex
raised (the pool-scan-then-interface-scan order becomes unambiguous).

### 5.8 Observability (round-1 Codex major 9 — descoped deliberately)

No new control-status/API field in this PR (keeps "no API change" true).
PAT collisions ride: a crate-internal `AtomicU64` asserted by tests;
`debug_log!` on the PAT transition (cold path, per-admission); the existing
`record_source_nat_failure` event path on exhaustion; and operator
visibility through the ALREADY-generic session display
(`show security flow session` renders `rewrite_src_port`). Registry
occupancy/holder/exhaustion status plumbing (protocol/control.rs:343 +
protocol_status.go:287 precedent) is a named follow-up, not this PR.

## 6. Public API preservation

Preserved byte-for-byte: `NatDecision`, `SourceNatLookup`, `SessionKey`,
`SyncedSessionEntry`, the HA session-sync wire, the Go→helper snapshot
protocol (`SourceNATRuleSnapshot` gains NO fields), the helper control
status wire, all CLI/gRPC surfaces. Changed signatures are
`pub(crate)`-internal only: `match_source_nat_result_for_tuple` (+1 arg),
`match_source_nat_for_flow_result_at` (+1), `source_nat_decision_for_flow`
(+1), `source_nat_would_translate_fragment` (+1),
`release_source_nat_allocation` / `rollback_source_nat_allocation` /
`reserve_synced_source_nat_allocation` (+2 each: registry + worker id), the
coordinator test helper, and the nine release sites' call expressions. Go
change is confined to the #5144 validator extension + its tests.

## 7. Hidden invariants the change must preserve

- **Probe purity (both classes)**: `non_first_fragment == true` OR
  `tuple_unknown == true` mints NOTHING (#6122 contract +
  nat/source.rs:1109 synthetic wrapper; round-1 SMR B1 / Codex major 5).
- **Single-CS mint**: identity check + insert under ONE `live` mutex
  acquisition (the `reserve_address_only` shape); no lock-free pre-claim
  exists to race the insert (round-1 AGY blocker 1 / SMR M5 cannot occur).
- **Idempotent re-entry**: a second packet of the same flow returns the
  existing translation; no double-mint (RSS pins a flow to one worker;
  the path covers worker-reconfig + HA replays).
- **Release symmetry**: every mint frees through the existing teardown
  sites — no new delete site (the #4388/#5269 doctrine); rollback frees
  pre-install aborted mints; holder-set empties before identity free.
- **Never-steal**: synced reserve fails rather than evict a different
  flow's live identity; graceful skip on drift (#4388 posture).
- **Holder replay idempotence**: sync refresh/replace re-reserve is a
  set-no-op; promote/demote/materialize make no calls (round-1 Codex
  blocker 3).
- **Registry lifetime**: node-lifetime; never rebuilt, never aliased per
  generation, per-address allocators never dropped (round-1 Codex blocker
  2 / AGY blocker 2).
- **NatDecision freeze**: no new fields; `rewrite_src_port: Some(_)` on an
  interface-mode decision is the only new observable state and every
  consumer handles it from pool mode (§4 item 6 audit).
- **Hot path**: established-flow transit untouched; zero new per-packet
  work; admission-only registry `RwLock` read; 1:N multimaps return to
  len-1 inline buckets for interface SNAT.
- **Logging**: no per-packet logging; PAT transitions use `debug_log!`
  (cold admission path only).

## 8. Risk assessment

| Class | Rating | Notes |
|---|---|---|
| Behavioral regression | LOW-MED | Wire change only for flows ambiguous on the wire today (later collider PAT'd); non-colliding flows byte-identical incl. sub-1024 ports and cross-dst port sharing (round-1 Codex major 6 redesign). Pinned tests at session/tests.rs:4560/4602 stay GREEN (direct-install pins bypass admission) — one re-pointed at a live collision class, one annotated (§9). Mixed-version HA window documented (§5.4). |
| Lifetime / borrow-checker | LOW | Registry is `Arc<PortAllocator>` clones out of a node-lifetime `RwLock` map; same shape as the shared session maps. |
| Performance regression | LOW | Admission-only: registry read + one `live` mutex identity mint per NEW interface-mode flow; PAT probe only on collision (bounded 4096); zero per-packet cost. |
| Architectural mismatch | LOW | Built verbatim on the shipped #5269 token machinery + #5144 validator pattern + shared-maps placement; no new subsystem, no packet-path scan. |

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
  collider fail-closed; PAT probe budget → `AllocatorExhausted`; idempotent
  re-entry (same flow twice, same tuple, one mint); cross-rule same-egress
  collision detected (one registry); BOTH probe classes mint nothing
  (non_first_fragment / tuple_unknown); rollback frees; reserve_synced
  mirrors exact identity, never steals; holder set (sibling replica reap
  does not free the owner's identity — RED on the #6522 shape; replay
  re-reserve is a no-op; last-holder reap frees).
- Go validator tests: interface-egress-address vs source-pool overlap →
  strict reject + tolerant warn; vs NAT64 pool overlap → same; no-overlap
  pass; unreferenced-pool scoping unchanged.
- Existing pins: session/tests.rs:4560/4602 stay GREEN; ONE re-pointed at a
  live non-bijective class (DNAT-to-shared-backend) so the multimap pin
  covers an admission-reachable class, the OTHER annotated that
  direct-install bypasses admission (round-1 SMR M7 / AGY nit 7); the
  #4399/#4438/#5269/#5336 suites unchanged.
- Smoke (loss userspace cluster, lock protocol per CLAUDE.md): two test
  hosts behind interface-mode SNAT, same source port to the same target —
  both flows establish, distinct external ports observed on the WAN side
  (tcpdump), replies land on the correct host; same-id ping pair both get
  replies; `make test-failover` (HA reserve adjacency). Helper-restart
  rehydration: restart the helper on the standby, verify reserves rebuild
  from HA re-sync (round-1 Codex major 8 test gap).
- Docs sweep: docs/userspace-dataplane-architecture.md (interface-mode
  bullet + #4399 1:N section collision-class list),
  docs/userspace-dataplane-gaps.md:44 row, `_Log.md`.

## 10. Out of scope (explicitly)

- Pool allocator holder fix (#6522) — the new registry ships with the
  holder model; pool keeps its known exposure until #6522 lands.
- Junos-literal always-PAT (translate every interface-mode admission) —
  larger wire change, no correctness gain (§4 documents preserve-first as
  the intentional xpf semantic, not claimed literal parity).
- Config knobs for the interface-mode port range / PAT-probe budget (fixed
  1024-65535 / 4096); helper status + Go mirror for registry occupancy
  (§5.8 follow-up).
- Transactional reserve-before-install / quarantine for sync-import
  conflicts (§5.6 documents the #4388 graceful-skip posture).
- #2387 session-identity enrichment — orthogonal; the colliding flows share
  every context, so #2387 alone would NOT fix this issue.
- DNAT-to-shared-backend / NAT64 / static non-bijective classes — covered
  by the shipped 1:N multimaps; unchanged.
- ALG payload rewriting for PAT'd ports (same posture as pool mode today);
  netflow/syslog translated-port fields (already generic per §4 item 6
  audit).

## 11. Open questions for adversarial review

1. Holder model: is the per-worker holder SET (§5.6) the right acquisition
   identity, or do reviewers demand the acquire/release ride the
   session-table install/remove choke points directly (the
   `session_limit_inc`/`remove_entry` precedent, install.rs:232/446/580)?
   Both were analyzed; the set model won on replay idempotence — attack it.
2. §5.7 validator: is extending #5144 to interface-mode egress addresses
   the right foreclosure, or must the dataplane ALSO defensively
   cross-probe pool allocators on the interface mint (belt-and-suspenders
   for the tolerant-load window before the validator rejects)?
3. Mixed-version window (§5.4): accept the documented window, or gate
   `SessionSyncProtocol` and break HA sync during rolling upgrades? Which
   doctrine wins?
4. PAT probe budget 4096 (statistically exhaustive) vs a full
   identity-space scan fallback vs `Unavailable` on first probe failure —
   is the bounded randomized probe the right exhaustion posture?
5. Preserve-first vs Junos-literal always-PAT: the semantic is now
   presented as an intentional xpf choice (Junos allocates unconditionally);
   does any reviewer demand literal parity instead?
6. (b)'s identity-squatting DoS vs (a)'s probe complexity: does the DoS
   vector hold (insider squats a victim's (port, server) identity), and
   does it settle the fork for (a)?
7. Should the sync-import reserve cap mirror pool (uncapped, HA fidelity)
   or enforce `max_tracked_flows` (fail imports under pressure)? §5.6 chose
   pool parity — attack.
8. Is PLAN-KILL (option (c)) defensible for a High security finding given
   the mechanism is now ~verbatim reuse of shipped machinery? Under what
   risk calculus?
