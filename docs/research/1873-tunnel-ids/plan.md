# #1873 — Stable tunnel-endpoint IDs across config commits

## 1. Status

DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR).

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
hit it — which is why it survived. The fix candidate (Path A) is a
~40-line Go-only change in one function plus tests; no wire-format
change, no Rust functional change, no hot-path change. The risk is
concentrated in getting the determinism story right (cross-node and
cross-restart agreement) and in the collision/reuse residuals
documented below.

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

### Path A (RECOMMENDED): deterministic content-derived ids

Replace the positional counter with a pure function of the interface
name, computed only in Go:

```go
// stableTunnelEndpointID maps an interface name (e.g. "wg0.0",
// "gr-0/0/0.0") to a stable nonzero u16. FNV-1a 64 folded to 16 bits,
// then mapped into [1, 0xFFFF]. THE HASH IS WIRE-ADJACENT AND MUST
// NEVER CHANGE: both cluster nodes must compute identical ids from
// identical config (cluster session-sync carries the bare number in
// SessionValue.FibGen).
func stableTunnelEndpointID(name string, used map[uint16]string) uint16 {
    h := fnv.New64a()
    h.Write([]byte(name))
    s := h.Sum64()
    folded := uint16(s ^ (s >> 16) ^ (s >> 32) ^ (s >> 48))
    id := folded%0xFFFF + 1 // [1, 0xFFFF], never 0
    for i := 0; i < 0xFFFF; i++ {
        if owner, taken := used[id]; !taken {
            return id
        } else if owner == name {
            return id // idempotent re-entry (defensive)
        }
        slog.Warn("tunnel endpoint id collision, probing",
            "name", name, "id", id)
        id = id%0xFFFF + 1 // linear probe, wraps, skips 0
    }
    return 0 // >65534 tunnels: unreachable in practice
}
```

`buildTunnelEndpointSnapshots` keeps its existing sorted-name iteration
and eligibility gates; `addEndpoint` calls `stableTunnelEndpointID`
instead of `nextID++` and records `used[id] = ifName`. The function
stays pure — no Manager state, no persistence, no new locks.

**Why this satisfies every consumer:**

- *Engine reuse / wg_control / GRE origin threads*: an unchanged
  tunnel keeps its id across any add/remove → `wg_identity_unchanged`
  compares the same tunnel against itself → Arc reuse holds; engine
  ptr unchanged → no thread churn. Zero Rust changes.
- *Live sessions*: ids never remap for surviving tunnels. A REMOVED
  tunnel's id dereferences to nothing — `tunnel_endpoints.get(&id)`
  returns `None` → `frame/wg.rs:53` / `gre.rs:308` drop the frame
  (fail-safe, verified: both are `?` early-returns). Re-adding the
  same name restores the same id → sessions resume. This answers the
  load-bearing "live sessions across id-remap" question: **there is no
  remap anymore; removal becomes a drop, not a misdirect.**
- *HA agreement*: both nodes compute ids from config content alone —
  same config ⇒ same ids, independent of build history, daemon
  restarts, or commit ordering. During a config-sync timing window,
  tunnels NOT being edited keep identical ids on both nodes (today
  every tunnel sorting after the edit drifts).
- *Restart*: pure function ⇒ stable across daemon/helper restarts; no
  persisted allocation file, nothing to fsync, nothing to migrate.

**Residual risks (honest):**

1. *Hash collision* (two configured names fold to the same u16):
   probability ≈ N(N-1)/2 ÷ 65535 ≈ 0.2% at 16 tunnels, 1.7% at 48.
   Handled deterministically by sorted-order linear probing; a
   collision makes the probed name's id depend on the colliding set
   (removal of the earlier chain member shifts the later one — the
   positional bug, but confined to the colliding pair and logged).
2. *Id reuse hazard*: remove tunnel A (id X), then add tunnel B whose
   hash is X → A's surviving stale sessions mis-resolve into B until
   they expire. Probability per add ≈ 1/65535 — versus today's
   CERTAINTY for every later-sorting tunnel on every add/remove.
3. *Mixed-version cluster window* (ISSU): old node computes positional
   ids, new node computes hash ids → cross-node tunnel-session sync
   degraded (peer resolves an unknown id → `EgressIfindex=0` →
   NoRoute on the synced copy) until both nodes upgrade. Non-tunnel
   sessions unaffected. Same failure class the bug already causes on
   every commit; bounded by the upgrade window. Documented in the
   upgrade notes; no compat shim (a shim would need the peer's version,
   which the sync protocol doesn't carry).
4. *Test updates*: `manager_test.go:2175` asserts `ID == 1`;
   `tunnels_test.go` fixtures assume 1..N. These become
   name-derived-value assertions (compute expected via the same
   helper, and pin one literal value as a hash-freeze guard).

### Path B: name-keyed maps end-to-end (drop numeric ids)

Carry the tunnel NAME instead of the id everywhere. Killed by three
hard constraints: (1) `SessionDecision.resolution` lives in per-packet
hot structs — a `String` there violates the hot-path allocation rules
(interning it = numeric ids again); (2) the event stream payload is a
fixed binary layout (u16 at [16:18]); (3) the cluster sync protocol is
a fixed binary `SessionValue` mirror (`sync_protocol.go` hand-rolled
offsets) — adding a variable-length name is a versioned wire break
across an HA pair mid-upgrade. Cost wildly exceeds Path A for the same
outcome. **Not recommended.**

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
- Rust: zero functional changes (one new contract test only).

## 7. Hidden invariants the change must preserve

1. **Determinism**: same `cfg` ⇒ same id set, regardless of process
   history, map iteration order (Go map iteration is randomized — the
   existing `sort.Strings(names)` + `sort.Ints(unitNums)` ordering is
   what makes probing deterministic; the plan keeps assignment inside
   that loop).
2. **Hash freeze**: the fold function is effectively wire-adjacent
   (cross-node agreement). A literal-value pin test freezes it.
3. **Nonzero ids**: id 0 means "not a tunnel" everywhere
   (`endpoint.id == 0` skip at `forwarding_build/tunnels.rs:17`,
   `tunnel_endpoint_id != 0` gates across the hot path). The mapping
   `folded%0xFFFF + 1` can never produce 0.
4. **Eligibility-independent identity**: the id depends only on the
   name, never on which OTHER tunnels passed the eligibility gates
   (source/dest present, iface up). Probing order does depend on the
   eligible SET under collision — documented residual #1.
5. **No Manager state / no locks**: builder runs on the commit path
   and in tests without a Manager; keeping the function pure preserves
   that.
6. **Session-resolution fail-safe**: absent id ⇒ drop (`?` on
   `tunnel_endpoints.get`), never plaintext fallback. Verified at
   `frame/wg.rs:53`, `gre.rs:308`; `cached_session_resolution`
   fallback retains `tunnel_endpoint_id` so the encap gate still sees
   the tunnel marking (`session_glue/mod.rs:18-41`).

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW-MED | Values of ids change once at upgrade (one-time engine rebuild + synced-session resync at the upgrade boundary — equivalent to what every commit does today). After that, strictly more stable. |
| Lifetime / borrow-checker | NONE | Go-only; Rust untouched. |
| Performance regression | NONE | Commit-path only; one FNV hash per tunnel per snapshot build. |
| Architectural mismatch | LOW | Numeric u16 identity is kept (hot-path + wire constraints demand it); only the allocator changes. The alternative architectures (B/D) were evaluated and rejected above, not deferred. |

## 9. Test plan

- Go unit (new, `tunnels_test.go`):
  - add/remove-middle pins: build with {A,B,C}, rebuild with {A,C} —
    A and C keep their exact ids; rebuild with {A,B,C,D} — A,B,C keep
    ids.
  - determinism pin: two independent builds of the same config produce
    identical id sets (exercises map-iteration randomization).
  - hash-freeze pin: one literal expected id for a fixed name (e.g.
    `wg0.0`) — fails loudly if anyone touches the fold.
  - collision pin: brute-force two names with equal folds in-test,
    assert deterministic probe result and that a NON-colliding third
    name is unaffected by the colliding pair's membership.
  - update `manager_test.go:2175` + `tunnels_test.go` positional
    assertions.
- Rust contract test (`forwarding_build/tests.rs`): two snapshots
  where a middle endpoint is removed but the others keep their ids —
  assert `populate_wg_engines` preserves engine Arc identity
  (`Arc::ptr_eq`) for the survivors. Pins the contract the Go
  allocator now guarantees (today this scenario is exactly what
  breaks).
- Full gates: `cargo build --release`, full `cargo test --release`
  (awk-aggregated), `go test ./...`.
- Live (cluster, with-cluster.sh lock protocol): bring up TWO WG
  tunnels (wg-interop harness configure + a manual second stanza),
  confirm both `session_confirmed=1` via #1876 telemetry; remove the
  FIRST tunnel; prove the second survives: `session_confirmed` stays
  1, `hs_completions_*` do NOT re-increment, traffic through tunnel 2
  uninterrupted. Repeat the inverse (re-add tunnel 1) — tunnel 2 still
  undisturbed.
- HA agreement check: same committed config on fw0/fw1 → identical
  `tunnel_endpoint_id` in `show ... wireguard` / status output.

## 10. Out of scope (explicit)

- GRE local-origin threads are spawned at bringup only
  (`reconcile/bringup.rs:445`) — a runtime-added GRE tunnel gets no
  origin thread until restart. Pre-existing, orthogonal; file a
  follow-up issue if confirmed undocumented.
- Carrying tunnel NAMES on the cluster/event-stream wire (Path B
  machinery) — unnecessary under Path A.
- Session migration for genuinely-changed WG identities (#1432 S5).
- Any persistence of id allocations to disk.
- Mixed-version compat shim for the one-time upgrade re-id (documented
  instead).

## 11. Open questions for adversarial review (each may PLAN-KILL)

1. Is the **mixed-version upgrade window** (residual 3) acceptable
   without a shim? The HA pair will degrade tunnel-session sync until
   both nodes run the new allocator. If a reviewer can show a
   persistent (not window-bounded) failure mode, that kills Path A as
   specified.
2. Is the **collision-probe order-dependence** (residual 1)
   acceptable, or must collisions be a hard commit error? A commit
   error is simpler to reason about but turns a 0.2%-at-16-tunnels
   event into a user-visible commit failure with no remediation other
   than renaming an interface.
3. Is the **reuse hazard** (residual 2: removed-tunnel sessions
   mis-resolving into a hash-colliding NEW tunnel) acceptable at
   ~1/65535 per add, or does it demand the A+D tombstone hybrid
   despite its cross-node divergence cost? (We argue divergence is
   strictly worse — it breaks the COMMON case to harden a rare one.)
4. Did the consumer map miss an id surface? Specifically checked:
   flow cache (generation-stamped, safe), routes (rebuilt per state),
   telemetry (#1876, name-keyed), `wgfmt.go`/status display
   (informational), `bpf_map`/segmentation/dispatch boolean gates.
   Anything that ASSUMES dense/small ids would break at id 65000.
   `FastMap<u16, TunnelEndpoint>` and `BTreeMap<u16, _>` are fine;
   reviewers should hunt for any array-by-id or `as usize` indexing
   we missed.
5. Should the Go side ALSO re-stamp `val.FibGen` on snapshot change
   (Go shadow conntrack entries keep the id the helper reported at
   session creation)? Under Path A the stored id stays correct for
   surviving tunnels and dangles harmlessly (NoRoute on peer) for
   removed ones — we claim no re-stamping is needed. Counter-trace
   welcome.
6. The eligibility gates (`ifaceByName` presence, GRE source/dest)
   mean a tunnel can drop OUT of the snapshot without a config
   removal (e.g. interface briefly absent at build time). Under
   positional ids this ALSO renumbered everyone else (live bug!);
   under Path A it only removes that tunnel's id transiently. Is
   there a consumer for which transient id absence is WORSE than
   today's transient renumber? (We found none — absent ⇒ drop,
   shifted ⇒ misdirect.)
