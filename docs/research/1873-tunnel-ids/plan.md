# #1873 — Stable tunnel-endpoint IDs across config commits

## 1. Status

DRAFT v3 — round-2 verdicts: Claude SMR PLAN-NEEDS-REVISION
(claude-smr-plan-r2.md), Codex PLAN-NEEDS-REVISION
(task-mqa5478t-h5yale), AGY PLAN-NEEDS-REVISION
(adversarial-review-mqa540ex-4eud0g). All round-2 required changes
incorporated; pending round-3 review.

### Round-2 convergence summary

- **All three converge on the same R-C defect**: v2 scoped the drop
  gate to forwarded-frame BUILD FAILURES, but tunnel-marked decisions
  reach slow-path reinjection through more doors — Codex enumerated
  them all (build failure `tx/dispatch/mod.rs:575,855`; FabricRedirect
  missing-binding `Owned` frames `tx/dispatch/mod.rs:223-225`;
  `poll_descriptor/mod.rs:2164` LocalDelivery; `poll_descriptor/
  mod.rs:2763` non-forward dispositions — `resolve_tunnel_forwarding_
  resolution` preserves `tunnel_endpoint_id` on NoRoute/
  MissingNeighbor, `forwarding/mod.rs:1534,1539`). v3 R-C is a single
  invariant at the `maybe_reinject_slow_path_from_frame` chokepoint.
- **Claude SMR r2 MAJOR (cold-path preservation)**: a BLANKET
  tunnel-marked drop would break the designed cold path — slow-path
  reinjection of a RESOLVABLE tunnel's inner packet is how
  pre-handshake WG traffic reaches the kernel wgN route → TUN →
  `wg_control` encrypt (`wg_control.rs:120-126,214-249,547`) and how
  GRE corner traffic reaches the kernel GRE netdev. v3's gate is
  therefore CONDITIONAL: reinject iff the id resolves in the current
  `ForwardingState`, drop+count otherwise. The conditional-vs-
  unconditional question is pinned for round 3 (§11 Q1).
- **AGY r2 MAJOR (verified)**: `retry_pending_neigh`
  (`neighbor_dispatch.rs:200-260`) TXes buffered frames via
  `rewrite_forwarded_frame_in_place` (MAC/VLAN/NAT only — no encap);
  tunnel-marked packets buffered on outer MissingNeighbor would be
  transmitted PLAINTEXT on neighbor resolution (no tunnel gate exists
  at the `pending_neigh` enqueue — verified). v3 adds R-E.
- **Claude SMR r2 MINOR**: R-B commit check must be symmetric across
  cluster nodes — run it over the union of tunnel names across all
  `groups` blocks + main hierarchy, not the per-node effective config.
- Codex/AGY r2 ratified with file:line evidence: Q1 mixed-version
  window (self-healing — per-packet re-resolution), Q2 fail-closed,
  Q3 R-D propagation (Close deltas → `daemon_ha_userspace.go:765` →
  `sync_conn.go:832` `DeleteWithCompanions*`; standby purge does not
  resync back, `daemon_ha_userspace.go:566`), Q4 no dense-id
  consumer, Q5 no FibGen re-stamp, Q7 R-D necessary (wrong-tunnel
  encap on reuse is invisible to R-C), Q8/AGY GRE-origin out-of-scope
  call CORRECT.

### Round-1 convergence summary

- **All three**: id assignment must be a pure function of CONFIG
  content — v1 assigned ids after the runtime eligibility gates, so
  link flaps could shift colliding ids and diverge HA nodes. Fixed in
  §5 (config-domain assignment).
- **Codex MAJOR 1** (verified worked pair: `wg1408.0`/`wg78.0` both
  fold to 824 under the planned FNV fold — reproduced locally):
  collision probing preserves a deterministic wrong-tunnel remap.
  Fixed: probing REMOVED, collisions fail closed at commit check
  (§5 R-B), plus apply-time session purge on id owner change (§5 R-D).
- **AGY Finding 1 (CRITICAL, verified in code by Claude SMR)**: v1's
  "absent id ⇒ drop" fail-safe claim is WRONG. A failed tunnel encap
  build sets `fallback_to_slow_path = true`
  (`tx/dispatch/mod.rs:575-578`) and
  `maybe_reinject_slow_path_from_frame` (`slow_path.rs:129`) has no
  disposition/tunnel gate — the UNENCAPSULATED inner L3 packet is
  enqueued to the slow-path TUN where the kernel routes it: plaintext
  leak. (Codex r1's contrary "absent IDs drop, not plaintext" note
  examined only the `?` early-returns inside the builders, not the
  caller's None handling — the leak stands.) Fixed: §5 R-C drop gate
  + §5 R-D purge.
- **Codex MAJOR 3**: two-WG-tunnel live validation collides with the
  S2a single-WG-listen-port shim plumbing (`maps_sync.go:1541`).
  Fixed: §9 uses a GRE + WG tunnel pair.
- **AGY Finding 3**: GRE local-origin threads run on a frozen
  `ForwardingState` across `refresh_runtime_snapshot` (verified:
  `helpers.rs:539` excludes tunnel ifaces from the binding-plan key;
  only `bringup.rs:445` spawns sources). Held OUT of scope with
  justification in §10 — pre-existing lifecycle defect reproducible
  with zero id changes; follow-up issue to be filed with AGY's trace.

## 2. Issue framing

`buildTunnelEndpointSnapshots` (`pkg/dataplane/userspace/tunnels.go:44`)
assigns tunnel-endpoint ids positionally: `nextID` 1..N over
alphabetically-sorted interface names. Adding or removing ONE tunnel
interface renumbers every endpoint that sorts after it. The numeric id
is the identity by which BOTH sides key everything:

- **Rust WG engine reuse** (`forwarding_build/wg.rs:56-66`):
  `populate_wg_engines` compares prev/next endpoints **at the same id**
  via `wg_identity_unchanged`. An id shift compares two *different*
  tunnels → compare fails → fresh `WgEngine` → live transport sessions
  dropped + TAI64N reseed on a commit that did not touch that tunnel.
- **WG control-thread churn** (`coordinator/mod.rs spawn_wg_control_threads`):
  `wg_control_threads: BTreeMap<u16, _>` stale-prunes on engine-Arc
  change → stop/join/respawn (socket rebind, TUN reopen) for every
  shifted id.
- **Live-session wrong-tunnel encap** (worst defect, found in this
  research): `SessionDecision.resolution.tunnel_endpoint_id` is stored
  in worker session tables and synced-session entries, and is
  re-resolved per packet against the *current* `ForwardingState`
  (`session_glue/mod.rs:91` → `resolve_tunnel_forwarding_resolution`;
  `frame/wg.rs:51-53`; `gre.rs:308`). Sessions are NOT flushed on
  commit (only the flow cache is generation-stamped,
  `flow_cache.rs:666`). After a renumbering commit, a live session's
  stored id dereferences to whichever tunnel NOW holds that id —
  traffic for tunnel A is encapsulated into tunnel B. For WG that means
  the inner packet is encrypted under the WRONG peer's session and
  delivered to that peer (cross-tunnel data leak); for GRE it goes to
  the wrong outer destination.
- **GRE local-origin threads** (`coordinator/mod.rs:434`):
  `spawn_local_tunnel_sources` runs at bringup only and each thread
  captures its `tunnel_endpoint_id`; after a renumbering commit the
  thread dereferences an id that may now belong to a different tunnel.
- **HA id drift**: the id crosses the cluster as a bare number with no
  name alongside: Rust session delta → event stream byte [16:18]
  (`event_stream/codec.rs:209`, `eventstream.go:736`) → Go shadow
  conntrack `val.FibGen` + `LogFlagUserspaceTunnelEndpoint`
  (`daemon_ha_userspace.go:228`) → cluster sync fixed binary layout
  (`pkg/cluster/sync_protocol.go:154/239/371/472`, LE u16 at fixed
  offset) → peer Go `buildSessionSyncRequestV4/V6` resolves the
  ORIGIN node's number against the PEER's `lastSnapshot`
  (`manager_ha.go:745-757`) → peer helper installs it raw into
  `SyncedSessionEntry` (`server/helpers.rs:301,353`). Ids only agree
  because both nodes run the same positional algorithm over the same
  (synced) config; during config-sync timing windows every id after
  the edited tunnel disagrees, so synced sessions reference the wrong
  endpoint until resync.

## 3. Honest scope/value framing

This is a correctness/security bug, not a perf issue. Blast radius of
the defect: any multi-tunnel deployment that edits tunnel config at
runtime. Single-tunnel deployments (the current smoke topology) never
hit it — which is why it survived. The fix (Path A v2) is: a small
pure-function allocator change + commit check in Go (R-A/R-B), a
conditional tunnel gate at the slow-path reinjection chokepoint
(R-C — closes a verified pre-existing plaintext-leak fallback while
preserving the designed kernel cold path), tunnel exclusion from the
in-place pending-neighbor TX path (R-E — a second verified plaintext
door), and an apply-time session purge for remapped ids (R-D). No
wire-format change, no
steady-state hot-path change. The risk is concentrated in the two
Rust guards (failure-path semantics, purge correctness) and the
documented upgrade-boundary residuals.

*If reviewers conclude the defect is better fixed by a different
identity mechanism — or that the residual risks of the recommended
path outweigh the positional bug — PLAN-KILL or PLAN-PIVOT is an
acceptable verdict.*

## 4. What's already shipped / composes with this

- **#1868** (interop + S2a fixes), **#1872** (#1866 tombstone
  lifecycle): `hydrate_wg_identity` + `WgRowIdentity`
  (`forwarding_build/tunnels.rs:110-199`) is the single source of
  truth for WG identity hydration; `wg_control_threads` entries carry
  engine-ptr + attachment identity and tombstone on exit. All keyed by
  the numeric id — they become correct-by-construction once ids are
  stable. No changes needed there.
- **#1876** (#1865 WG telemetry): counter rows are keyed by tunnel
  NAME precisely to dodge this bug (`metrics_userspace.go:59`
  comment cites #1873; `status.rs:660-696` name fallback chain). The
  telemetry is also our live-validation instrument: `session_confirmed`
  and `hs_completions_*` per tunnel name prove engine survival.
- **Flow cache** is already generation-stamped
  (`config_generation`/`fib_generation`, `flow_cache.rs:666`) — safe
  today, unaffected by this change.
- Wire fixture `userspace-dp/tests/fixtures/protocol_wire_v1.json` has
  `"tunnel_endpoints": []` — ids are values, not schema; **no fixture
  regen and no serde change** under Path A.

## 5. Concrete design — four paths

### Path A (RECOMMENDED, v2): pure hash ids, fail-closed collisions, remap purge

Five coordinated pieces (R-A..R-E). The id of a tunnel endpoint is the
hash of its config name, full stop — no probing, no history, no
runtime-state input.

**R-A: config-domain assignment (all 3 reviewers, round 1).** The id
function lives in `pkg/config` (importable by both the compiler's
commit check and `pkg/dataplane/userspace`):

```go
// config.StableTunnelEndpointID maps a tunnel interface name (unit-
// qualified, e.g. "wg0.0", "gr-0/0/0.0") to a stable nonzero u16:
// FNV-1a 64 xor-folded to 16 bits, mapped into [1, 0xFFFF]. THE FOLD
// IS WIRE-ADJACENT AND MUST NEVER CHANGE: both cluster nodes must
// compute identical ids from identical config (cluster session-sync
// carries the bare number in SessionValue.FibGen).
func StableTunnelEndpointID(name string) uint16 {
    h := fnv.New64a()
    h.Write([]byte(name))
    s := h.Sum64()
    folded := uint16(s ^ (s >> 16) ^ (s >> 32) ^ (s >> 48))
    return folded%0xFFFF + 1 // [1, 0xFFFF], never 0
}
```

`buildTunnelEndpointSnapshots` assigns `ID:
config.StableTunnelEndpointID(ifName)` inside `addEndpoint`; because
the id depends on the name ALONE, the eligibility gates
(`ifaceByName` presence at `tunnels.go:56`, GRE source/dest at
`tunnels.go:53`) can no longer influence ANY tunnel's id — a link
flap removes only that tunnel's row, never renumbering another. The
v1 `used`-map probing is deleted; the function stays pure (no Manager
state, no persistence, no locks).

**R-B: collisions fail closed at commit (Codex r1 MAJOR 1).** Two
configured tunnel names with equal folds (verified example:
`wg1408.0` and `wg78.0` → 824) are a COMMIT ERROR, raised in the
`pkg/config` validation pass over all unit-qualified tunnel names
(same place other commit rejections live), with remediation in the
message: "tunnel endpoint id collision between X and Y — rename one
interface". The check runs over the UNION of tunnel names across all
`groups` blocks plus the main hierarchy (raw config), NOT the
per-node effective config (Claude SMR r2 MINOR): a collision
involving a `groups node0`-scoped name must fail commit identically
on BOTH nodes, or config-sync would split (originator accepts, peer
rejects). Union-checking is strictly more conservative and
config-content-deterministic. Belt-and-braces: `buildTunnelEndpointSnapshots`
independently drops the later-sorting collider with an Error log (a
snapshot must never carry two rows with one id even if validation is
bypassed). With probing gone, `id == StableTunnelEndpointID(name)`
is an unconditional invariant — an id can never silently migrate to
a different live name.

**R-C (v3): conditional tunnel gate at the slow-path chokepoint (AGY
r1 Finding 1 CRITICAL; rescoped per round-2 convergence).** Today a
tunnel-marked decision (`resolution.tunnel_endpoint_id != 0`) can
reach slow-path TUN reinjection of the UNENCAPSULATED inner packet
through four doors (Codex r2 enumeration): forwarded-frame build
failure (`tx/dispatch/mod.rs:575,855` → `slow_path.rs:60-73`),
FabricRedirect missing-binding `Owned` frames
(`tx/dispatch/mod.rs:223-225`), `poll_descriptor/mod.rs:2164`
(LocalDelivery), and `poll_descriptor/mod.rs:2763` (non-forward
dispositions — `resolve_tunnel_forwarding_resolution` returns
NoRoute/MissingNeighbor WITH the id preserved,
`forwarding/mod.rs:1534,1539`). If the tunnel's kernel netdev/route
are gone (removed tunnel), the kernel default-routes the inner
packet: plaintext leak.

Fix — ONE invariant enforced at the single chokepoint
`maybe_reinject_slow_path_from_frame` (every door above funnels
through it), after the `local_tunnel_deliveries` LocalDelivery branch
(which must stay open — GRE local-origin inbound delivery, keyed by
`local_ifindex`), before `slow_path.enqueue`:

> A tunnel-marked inner packet may be reinjected to the kernel
> slow path ONLY while its `tunnel_endpoint_id` resolves in the
> CURRENT `ForwardingState`; otherwise drop + bump a new
> `tunnel_encap_unresolved` counter/exception.

The gate is CONDITIONAL, not blanket (Claude SMR r2 MAJOR): for a
RESOLVABLE id, kernel reinjection is the designed cold/slow path —
the kernel routes the inner packet into the wgN TUN, which
`wg_control` reads and ENCRYPTS (`wg_control.rs:120-126` open_tun,
`:214-249` TUN read, `:547` encap-and-send), or into the kernel GRE
netdev which encapsulates natively (`pkg/routing/tunnel.go`
tunnelManager). Pre-handshake WG traffic (`EncapError::NoSession` →
build None, `frame/wg.rs:101-106`) and missing-outer-neighbor
transit DEPEND on this; a blanket drop would regress cold-start.
Resolvability is the correct proxy for "the kernel still has the
tunnel": the same commit that removes the endpoint row removes the
netdev/route. (Conditional-vs-blanket is pinned as §11 Q1 for round
3.)

*Known residual (Claude SMR r3): VRF-table divergence.* The slow-path
reinjector is a plain `IFF_TUN` with no VRF binding
(`slowpath.rs:17-19`) — reinjected packets are routed in the main
table. A tunnel whose INNER route exists only in a routing-instance
table could have its reinjected packets default-routed. This is
PRE-EXISTING, tunnel-agnostic (non-tunnel VRF traffic reinjects the
same way), strictly REDUCED by the gate (absent ids now drop), not
fixable by blanket-drop (which only masks the tunnel-flavored
instance while regressing cold start), and owned by the S6/#1434
VRF-binding work. The conditional gate's correctness domain is
"kernel main-table view matches the userspace FIB for tunnel inner
routes" — true for the default-table tunnel configs supported on
this path today.

**R-E: keep tunnel-marked frames out of in-place TX paths (AGY r2
MAJOR, verified).** `pending_neigh` buffers frames awaiting OUTER
neighbor resolution; `retry_pending_neigh` then TXes them via
`rewrite_forwarded_frame_in_place` — MAC/VLAN/NAT rewrite only, NO
encapsulation (`frame/mod.rs:630-660`), so a tunnel-marked buffered
frame would go out PLAINTEXT on the physical wire when the neighbor
resolves (`neighbor_dispatch.rs:200-260`; no tunnel gate exists at
the enqueue sites — verified). Fix, two layers:
1. At the `pending_neigh` admission sites
   (`poll_descriptor/mod.rs:~2377,~2695`): tunnel-marked decisions
   are NOT buffered — route them to the R-C-gated reinjector instead
   (the kernel path performs its own neighbor resolution, so
   buffering is unnecessary for tunnel egress).
2. Defense-in-depth in `retry_pending_neigh`: a tunnel-marked entry
   (should now be unreachable) is dropped + counted, never
   in-place-TXed.

**R-D: apply-time session purge on id remap (Codex r1 MAJOR 1
required-change option, adopted).** Hash stability makes remaps rare
but not impossible (temporal reuse: remove A, later add B with
`hash(B) == hash(A)` while A's sessions still live — ≈1/65535 per
add; plus the one-time positional→hash re-id at upgrade). Close it
structurally: on snapshot apply (BOTH the full `reconcile` path and
`refresh_runtime_snapshot` — the latter is the common commit path
since tunnel ifaces are excluded from the binding-plan key,
`helpers.rs:539`), the coordinator diffs prev/next
`tunnel_endpoints` by id and collects ids that are (a) absent in
next, or (b) present with a DIFFERENT logical interface name (the
Rust `TunnelEndpoint` gains the logical `interface` name internally —
not a wire change; `interface_label` prefers linux_name and a
cosmetic rename must not purge). For each collected id: remove
matching entries from the shared synced/NAT/forward-wire session maps
and broadcast a worker command (alongside the existing
`FlushFlowCaches`-class commands) to drop session-table entries with
that stored `tunnel_endpoint_id`, routing deletions through the
existing session-delete machinery so HA delete-sync and the Go shadow
conntrack stay coherent. Result: no live session can ever forward
under an id whose owner changed; the in-flight race window within one
apply is covered by R-C's drop gate.

**Why this satisfies every consumer:**

- *Engine reuse / wg_control / GRE origin threads*: an unchanged
  tunnel keeps its id across any add/remove → `wg_identity_unchanged`
  compares the same tunnel against itself → Arc reuse holds; engine
  ptr unchanged → no thread churn.
- *Live sessions*: ids never remap for surviving tunnels. A REMOVED
  tunnel's sessions are purged at apply (R-D); any in-flight packet
  inside the apply window hits R-C's drop gate instead of the
  slow-path plaintext leak. Re-adding the same name restores the same
  id → new sessions establish normally. This answers the load-bearing
  "live sessions across id-remap" question: **surviving tunnels never
  remap; removal becomes purge+drop, never a misdirect or a plaintext
  fallback.**
- *HA agreement*: both nodes compute ids from config content alone —
  same config ⇒ same ids, independent of build history, daemon
  restarts, link state, or commit ordering. During a config-sync
  timing window, tunnels NOT being edited keep identical ids on both
  nodes (today every tunnel sorting after the edit drifts).
- *Restart*: pure function ⇒ stable across daemon/helper restarts; no
  persisted allocation file, nothing to fsync, nothing to migrate.

**Residual risks (honest, v2):**

1. *Hash collision at commit* (two configured names fold to the same
   u16): probability ≈ N(N-1)/2 ÷ 65535 ≈ 0.2% at 16 tunnels, 1.7% at
   48. Surfaces as a deterministic commit error with a rename
   remediation (R-B) — identical on both nodes, never a silent
   runtime behavior. A user upgrading WITH a colliding pair already
   configured sees the commit check fail on the first post-upgrade
   commit; the release note must call this out.
2. *Temporal id reuse*: closed by R-D's purge (owner-change detection)
   plus R-C's drop gate for the in-flight window. No longer a
   forwarding hazard; the residual is a session reset on a ~1/65535
   event.
3. *Mixed-version cluster window* (ISSU): old node computes positional
   ids, new node computes hash ids → cross-node tunnel-session sync
   degraded (peer resolves an unknown id → `EgressIfindex=0` →
   NoRoute on the synced copy) until both nodes upgrade. Non-tunnel
   sessions unaffected. Same failure class the bug already causes on
   every commit; bounded by the upgrade window. Documented in the
   upgrade notes; no compat shim (a shim would need the peer's
   version, which the sync protocol doesn't carry).
4. *Test updates*: `manager_test.go:2175` asserts `ID == 1`;
   `tunnels_test.go` fixtures assume 1..N. These become
   name-derived-value assertions (compute expected via
   `config.StableTunnelEndpointID`, plus literal pins as a
   hash-freeze guard — including the verified collision pair
   `wg1408.0`/`wg78.0` → 824).
5. *R-C/R-D are Rust hot-path-adjacent changes* (drop-gate condition
   on the build-failure path; apply-time purge walk). Both are
   commit-time or failure-path code, not steady-state per-packet
   work, but they widen the blast radius beyond v1's "Go-only" claim
   — reflected in §8.

### Path B: name-keyed maps end-to-end (drop numeric ids)

Carry the tunnel NAME instead of the id everywhere. Semantically this
is the SUPERIOR identity — names are injective, so collision and
temporal-reuse hazards vanish by construction (Codex r1, accepted
reword). It is killed on cost, not outcome-equivalence: (1)
`SessionDecision.resolution` lives in per-packet hot structs — a
`String` there violates the hot-path allocation rules (interning it =
numeric ids again, minus injectivity); (2) the event stream payload
is a fixed binary layout (u16 at [16:18]); (3) the cluster sync
protocol is a fixed binary `SessionValue` mirror (`sync_protocol.go`
hand-rolled offsets) — adding a variable-length name is a versioned
wire break across an HA pair mid-upgrade. Path A + R-B/R-D buys back
the injectivity guarantee (fail-closed collisions; purge on owner
change) at a tiny fraction of the cost. **Not recommended.**

### Path C: Rust-side content-compare (extend wg_identity_unchanged)

Make `populate_wg_engines` search the previous state for a
content-identical endpoint at ANY id, and key `wg_control_threads` by
content identity. Smallest diff conceptually, but: it only fixes WG
engine churn. The stored session ids still renumber (wrong-tunnel
encap remains), GRE origin threads still dereference shifted ids, the
Go-side `sessionSyncTunnelEndpointLocked` still mis-resolves, and HA
drift is untouched — the id is the cross-boundary identity and C
leaves it unstable. Also becomes dead code the moment ids are stable.
**Not sufficient; not recommended.**

### Path D: allocation map with tombstones (never reuse within runtime)

Manager keeps `map[name]uint16` + monotonic next-id; removed names
tombstone so ids are never repurposed within a daemon epoch. Gives
perfect node-LOCAL stability and eliminates the reuse hazard, but ids
become a function of per-node commit HISTORY: a node that restarted
(fresh map) or joined later allocates differently → PERMANENT
cross-node disagreement, and the cluster wire (FibGen, fixed binary)
cannot carry a name to compensate. Fixing that requires either
syncing the allocation map (new distributed state + bootstrap
ordering) or the Path B wire change. **Strictly worse than A for HA;
not recommended standalone.** (A+D hybrid — hash for cross-node
agreement, tombstones to block reuse — adds history-dependence back
the moment a tombstone influences probing, recreating the same
cross-node divergence. Rejected for the same reason.)

## 6. Public API / wire preservation

- `TunnelEndpointSnapshot` (Go `protocol.go:273`, Rust
  `protocol/snapshot.rs:309`): schema unchanged; `ID` stays `uint16`,
  values change meaning only (positional → content-derived). No serde
  change, no fixture regen, no `XPF_PROTOCOL_WIRE_REGEN`.
- `buildTunnelEndpointSnapshots(cfg, interfaces)` signature unchanged
  (stays a pure function — important: `snapshotContentHash` and the HA
  config-sync path both rebuild snapshots independently and must get
  identical ids).
- Cluster sync protocol, event stream layout, control-socket
  `SessionSyncRequest`: byte-identical schemas.
- Rust (v2): three bounded functional changes, none wire-visible:
  internal `TunnelEndpoint` gains the logical `interface` name field
  (R-D owner identity); the slow-path reinjection chokepoint gains
  the conditional tunnel gate (R-C); the pending-neighbor
  admission/retry paths gain tunnel exclusion (R-E); the coordinator
  apply paths gain the remap purge (R-D). No serde struct changes;
  no steady-state hot-path changes (gates sit on failure/cold
  paths).
- New `pkg/config` exported helper `StableTunnelEndpointID` + a
  commit-check validation (R-B) — additive API.

## 7. Hidden invariants the change must preserve

1. **Determinism**: same `cfg` ⇒ same id set — unconditionally, since
   v2 ids are per-name pure (`id == StableTunnelEndpointID(name)`).
   No dependence on process history, map iteration order, link state,
   eligibility gates, or the rest of the tunnel set.
2. **Hash freeze**: the fold function is effectively wire-adjacent
   (cross-node agreement). Literal-value pin tests freeze it
   (including the `wg1408.0`/`wg78.0` → 824 collision pair).
3. **Nonzero ids**: id 0 means "not a tunnel" everywhere
   (`endpoint.id == 0` skip at `forwarding_build/tunnels.rs:17`,
   `tunnel_endpoint_id != 0` gates across the hot path). The mapping
   `folded%0xFFFF + 1` can never produce 0.
4. **Id-owner injectivity**: at any instant, an installed id maps to
   at most one logical tunnel name (R-B fail-closed), and across
   applies an id whose owner changes is purged before the new owner's
   state is reachable by old sessions (R-D).
5. **No Manager state / no locks**: builder runs on the commit path
   and in tests without a Manager; keeping the function pure preserves
   that.
6. **A tunnel-marked inner packet leaves the box either ENCAPSULATED
   or NOT AT ALL** (R-C+R-E — replacing v1's incorrect "absent id ⇒
   drop" claim). Kernel reinjection counts as encapsulated ONLY while
   the id resolves (the kernel then owns the wgN/GRE encap); an
   unresolvable id drops at the chokepoint, and no in-place TX path
   may transmit a tunnel-marked frame.
7. **Node-scoped config caveat** (Claude SMR r1 R2): `groups nodeN`
   tunnel stanzas make the EFFECTIVE config differ per node by
   design; a node-scoped tunnel exists only in that node's id domain.
   Per-name hashing keeps all SHARED names in agreement regardless;
   nobody may later "fix" determinism by hashing whole-config
   context into the id.
8. **Purge identity is the logical config name**, never `linux_name`
   (a cosmetic kernel rename must not reset sessions) and never the
   telemetry `interface_label` (which prefers linux_name).

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | MED | Ids change once at upgrade (one-time engine rebuild + synced-session resync — equivalent to what every commit does today). R-C converts a (wrong) plaintext-forward behavior into a drop for unresolvable ids only — cold-path reinjection for resolvable ids is preserved (blanket drop would regress WG cold start). R-E drops tunnel frames that today would leak plaintext from the neighbor-retry path. R-D purge must not over-purge (guarded by logical-name identity, §7.8) or under-purge (guarded by tests). |
| Lifetime / borrow-checker | LOW | R-D needs prev/next state access in the coordinator apply paths — coordinator already holds both (`populate_wg_engines(state, previous)` pattern). No new shared ownership. |
| Performance regression | NONE | Commit-path + failure-path only; one FNV hash per tunnel per snapshot build; purge walk is O(sessions) once per apply with changed tunnel set. |
| Architectural mismatch | LOW | Numeric u16 identity is kept (hot-path + wire constraints demand it); the allocator becomes content-addressed and the runtime gains the two guards (drop gate, purge) that make numeric identity safe. B/C/D evaluated and rejected above, not deferred. |

## 9. Test plan

- Go unit (new, `tunnels_test.go` + `pkg/config`):
  - add/remove-middle pins: build with {A,B,C}, rebuild with {A,C} —
    A and C keep their exact ids; rebuild with {A,B,C,D} — A,B,C keep
    ids.
  - determinism pin: two independent builds of the same config produce
    identical id sets.
  - **eligibility-flap pin (Codex r1 M2 / AGY r1 rev 4)**: same config
    built with an interface absent from the `interfaces` snapshot vs
    present — every OTHER tunnel's id identical in both builds.
  - hash-freeze pins: literal expected ids for fixed names, including
    the collision pair `wg1408.0`/`wg78.0` → 824 — fails loudly if
    anyone touches the fold.
  - collision fail-closed pins: commit validation rejects a config
    with the colliding pair (clear two-name error); snapshot build
    drops the later-sorting collider and keeps the earlier.
  - update `manager_test.go:2175` + `tunnels_test.go` positional
    assertions.
- Rust contract tests:
  - `forwarding_build/tests.rs`: two snapshots where a middle endpoint
    is removed but the others keep their ids — `populate_wg_engines`
    preserves engine Arc identity (`Arc::ptr_eq`) for survivors.
  - **R-C pins (Codex r2 required-change test matrix)**: a
    tunnel-marked packet with an ABSENT id is dropped (no slow-path
    enqueue, `tunnel_encap_unresolved` increments) through each
    door: (a) build-failure fallback, (b) NoRoute disposition,
    (c) MissingNeighbor disposition, (d) FabricRedirect
    missing-binding `Owned` frame. PLUS the cold-path preservation
    pin: a tunnel-marked packet whose id RESOLVES (e.g. WG
    NoSession build failure) IS reinjected — blanket-drop
    regressions fail this test.
  - **R-E pins**: a tunnel-marked decision with outer
    MissingNeighbor is never admitted to `pending_neigh` (goes to
    the gated reinjector); a synthetic tunnel-marked entry forced
    into `pending_neigh` is dropped by `retry_pending_neigh`, never
    in-place-TXed.
  - **R-D pins**: apply a next-state where (a) an id vanished — its
    sessions are purged; (b) an id's logical name changed — purged;
    (c) an id's linux_name changed but logical name didn't — NOT
    purged; (d) untouched ids — sessions intact.
- Full gates: `cargo build --release`, full `cargo test --release`
  (awk-aggregated over all "test result" lines; known flaky ledger
  per project memory), debug `cargo test wg::`, `go test ./...`.
- Live (cluster, with-cluster.sh lock protocol; Codex r1 M3 — the S2a
  shim steers a SINGLE WG listen port, `maps_sync.go:1541`, so the
  second tunnel is GRE, not WG):
  1. Bring up the wg-interop WG tunnel (harness configure) + one GRE
     tunnel whose unit-qualified name sorts BEFORE the WG tunnel's
     (so the OLD positional scheme would renumber the WG endpoint on
     its removal — Claude SMR r1 R3).
  2. Confirm WG `session_confirmed=1` + traffic; note
     `hs_completions_*` counters and both nodes' endpoint ids.
  3. Remove the GRE tunnel (commit). Prove the WG tunnel survives:
     `session_confirmed` stays 1, `hs_completions_*` do NOT
     re-increment, no `wg-control … stopped/spawning` journal lines
     for the WG endpoint, traffic uninterrupted across the commit.
  4. Re-add the GRE tunnel — WG still undisturbed; GRE id identical
     to its pre-removal value (status output).
  5. **Stale-drop pin (Codex r1 M3)**: with traffic flowing through
     the GRE tunnel, remove IT — observe purge (session gone from
     `show security flow session`) and `tunnel_encap_unresolved`
     (or purge) accounting, and NO plaintext copies of inner packets
     on the WAN capture during the window.
  6. HA agreement: same committed config on fw0/fw1 → identical
     endpoint ids in status output on both nodes.

## 10. Out of scope (explicit)

- **GRE local-origin thread lifecycle (AGY r1 Finding 3 — verified,
  contested as scope).** The defect is real: tunnel ifaces are
  excluded from the binding-plan key (`server/helpers.rs:539-541`),
  so GRE config commits run `refresh_runtime_snapshot`, which never
  respawns local tunnel sources (`spawn_local_tunnel_sources` is
  called only from `reconcile/bringup.rs:445`); each source thread
  holds the `ForwardingState` Arc captured at spawn. Consequences
  exist with ZERO id changes — e.g. editing a GRE tunnel's
  destination is ignored by the origin thread until restart. That
  makes it a pre-existing lifecycle defect, not an id-identity
  defect: under Path A the thread's captured id remains correct for
  its tunnel, a removed tunnel's locally-originated traffic hits
  R-C/R-D, and a remapped id is purged. The fix it deserves is a
  three-pass reconcile mirroring #1866's wg_control work — its own
  plan + review cycle. **A follow-up issue with AGY's full trace will
  be filed at /engineer time and cross-linked here.**
- Slow-path VRF binding (reinjected packets route in the main table —
  pre-existing for ALL slow-path traffic, see §5 R-C residual; owned
  by the S6/#1434 VRF work).
- Carrying tunnel NAMES on the cluster/event-stream wire (Path B
  machinery) — unnecessary under Path A.
- Session migration for genuinely-changed WG identities (#1432 S5).
- Any persistence of id allocations to disk.
- Mixed-version compat shim for the one-time upgrade re-id (documented
  instead).

## 11. Open questions for adversarial review round 3 (each may PLAN-KILL)

Settled in rounds 1-2 (do not re-litigate without NEW evidence):
mixed-version window acceptable/self-healing (r2 Q1, both
reviewers); fail-closed commit error correct (r2 Q2); R-D
propagation sound via Close deltas, standby purge does not resync
back (`daemon_ha_userspace.go:566,765`, `sync_conn.go:832`); no
dense/array-by-id consumer (r1+r2 Q4); no FibGen re-stamp (r2 Q5);
R-D necessary, not over-engineering (r2 Q7); GRE local-origin
lifecycle out-of-scope call correct (AGY r2 Q8).

1. **Conditional vs blanket R-C gate** — the one open design
   divergence. Codex r2's required change asked for "any
   tunnel-marked decision must not enqueue to the kernel slow-path
   TUN"; v3 implements a CONDITIONAL gate (reinject iff id resolves)
   because the resolvable-id reinjection is the designed cold path:
   kernel routes the inner packet into the wgN TUN that `wg_control`
   reads and encrypts (`wg_control.rs:214-249,547`) or into the
   kernel GRE netdev that encapsulates natively. A blanket drop
   black-holes pre-handshake WG traffic and missing-outer-neighbor
   transit. Counter-evidence that the conditional gate still leaks
   plaintext somewhere (e.g. a case where the id resolves in
   `ForwardingState` but the kernel lacks the tunnel netdev/route
   for the inner destination NON-transiently) would force blanket +
   a userspace cold-path queue — a much bigger change. Reviewers:
   trace it or ratify the conditional gate.
2. **R-E admission rerouting**: v3 sends tunnel-marked
   MissingNeighbor packets to the gated reinjector instead of
   `pending_neigh`. Is any tunnel mode harmed by skipping the
   userspace outer-neighbor buffering (e.g. a transport table whose
   kernel-side route differs from the userspace FIB view)? Worked
   trace required to object.
3. **R-C/R-E counter visibility**: `tunnel_encap_unresolved` (+ the
   R-E drop counter) should surface in status/telemetry so the live
   validation can pin them. Any objection to extending
   `ProcessStatus` (additive JSON, both-sides serde default)?
4. **Purge-walk coverage**: R-D purges shared synced/NAT/forward-wire
   maps + worker session tables via Close deltas. Are there OTHER
   session stores holding `tunnel_endpoint_id` that the walk must
   visit (e.g. `recent_session_deltas` ring, eventstream replay
   buffers)? They are display/telemetry-only by our reading —
   confirm.
5. Any remaining hole in the v3 design that makes Path A worse than
   shipping nothing? PLAN-KILL remains a valid verdict.
