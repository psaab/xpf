# #1881 — GRE local-origin threads run on a frozen ForwardingState across refresh_runtime_snapshot

## 1. Status

DRAFT v2 — round-1 verdicts: Codex PLAN-NEEDS-REVISION
(task-mqadzerl-ygdn95), AGY PLAN-NEEDS-REVISION
(adversarial-review-mqadzm2h-gy3pg0), Claude SMR PLAN-NEEDS-REVISION
(claude-smr-plan-r1.md). All three endorse the Path D architecture.
v2 incorporates every required revision; pending round-2 review.

### v1 → v2 changes (mapped to reviewer findings)

1. **Rotation gate in the thread loop** (Codex MAJOR 1 / Codex R1):
   the store-before-prune window let a stale-attachment thread (same
   id, mode flip gre→wireguard, or reattachment) pass the #1873 owner
   check against the NEW state while reading the OLD TUN. New §D.1b:
   on every Arc rotation the thread re-validates its captured
   attachment (id present ∧ mode gre/ip6gre ∧ logical_ifindex+name
   match) and PARKS (drops without building) when invalid, until the
   coordinator prune joins it. Zero steady-state cost (computed only
   in the `load_arc_if_changed` Some-branch).
2. **Delivery shutdown ordering + drain stop check** (Codex MAJOR 2 /
   Codex R2; convergent with SMR-2/AGY R2 on live-only publication):
   unpublish stale senders BEFORE stop+join (store #1), final
   republish after spawns (store #2); add a `stop` check inside the
   delivery-drain inner loop so a busy producer cannot extend the
   join unboundedly.
3. **Single HA-state load per iteration** (AGY R1; Codex MEDIUM 3):
   `ha_state` was loaded twice per packet build (resolution
   enforcement + reverse-entry synthesis) — load once at the loop
   top next to the forwarding load and pass the loaded map down; the
   coherence claim is narrowed to "per-iteration ForwardingState +
   HA-map coherence" (HA is published independently of forwarding by
   design, `coordinator/ha.rs:39` — cross-source atomicity is not
   claimed, same as the worker path).
4. **Delivery channel is per-spawn-attempt, publication is live-only**
   (SMR-2, AGY R2): a fresh channel pair per spawn; only entries with
   a live handle are published; a failed spawn's sender is never
   published.
5. **Periodic liveness republishes the delivery map** (SMR-3, Codex
   R3) after sweep and after its ≤1 respawn.
6. **Spawn pass gated on live worker handles** (SMR-1): the deferred
   same-plan window (`defer_workers` true→true) reaches
   `refresh_runtime_snapshot` with zero workers; spawning there would
   freeze empty `live`/`identities`/`worker_commands` captures. The
   GRE spawn pass runs only when `!self.workers.handles.is_empty()`.
   WG deliberately has NO such gate (WG threads use kernel UDP+TUN,
   no binding dependency) — the asymmetry is intentional.
7. **F1 keepalive claim removed** (Codex MEDIUM 4 — verified:
   `pkg/routing/tunnel.go:304,567,615` probes the OUTER destination
   via `net.DialTimeout` over the underlay; keepalives do NOT ride
   the local-origin TUN path).
8. **GRE tombstone-respawn coherence gate specified** (AGY R3):
   existence + mode + attachment (snapshot row vs forwarding
   endpoint); endpoint CONTENT (dst/src/key) is deliberately NOT
   gated — post-fix, content flows through the ArcSwap, so a respawn
   never bakes content in.
9. **Distinct log prefix** for GRE lifecycle lines (AGY R4).
10. **Test plan extended** (Codex R5): same-id gre→wireguard flip,
    same-id attachment change, delivery-drain stop latency under a
    busy producer, liveness-respawn delivery republication, parked
    rotation-gate behavior; staleness pin phrased fails-on-master
    (SMR-4).
11. **Q2/Q7 closed** (SMR-6, Codex/AGY Q7): fatal-read recovery chain
    documented; severity framed as revocation-staleness +
    operational correctness, residual same-id window closed by §D.1b.

## 2. Issue framing

`spawn_local_tunnel_sources` (`userspace-dp/src/afxdp/coordinator/mod.rs:524`)
runs only from worker bring-up (`reconcile/bringup.rs:445`). Each GRE
local-origin thread captures, at spawn time:

- `let forwarding = self.forwarding.clone();` — a **frozen by-value
  clone** of the entire `ForwardingState` (mod.rs:540), passed to
  `local_tunnel_source_loop` (`afxdp/tunnel.rs:19`) as
  `forwarding: ForwardingState` and used per packet by
  `build_local_origin_tunnel_tx_request` (routes, tunnel endpoint
  rows, zones, CoS config, owner-RG map).
- `live` / `identities` / `worker_commands` — binding-plan-scoped
  handles (these only change across a full binding reconcile, which
  tears these threads down via `stop_inner` mod.rs:368-378, so frozen
  capture of THOSE is sound).
- `tunnel_endpoint_id` + `tunnel_name` — stable per #1873 (id is
  `config.StableTunnelEndpointID` of the unit-qualified interface
  name, `pkg/dataplane/userspace/tunnels.go:44`; editing the GRE
  destination/source/key does NOT change the id).

Tunnel interfaces are excluded from the binding plan
(`server/helpers.rs:651` `include_userspace_binding_interface` —
`if iface.tunnel { return false; }`), so a commit that only touches
tunnel config hashes to the SAME binding plan → the same-plan apply
leg (`server/handlers/snapshot.rs:95-110`) calls
`refresh_runtime_snapshot`, which:

- rebuilds `self.forwarding`, stores it into the worker-visible
  `Arc<ArcSwap<ForwardingState>>` (`ha_state.rs:14`,
  `self.ha.forwarding.store(...)` mod.rs:1156) — **workers pick the
  new state up next tick** via `load_arc_if_changed`
  (`worker/loop_body/mod.rs:306`, #1188 pattern);
- reconciles **WG control threads** (three-pass
  `spawn_wg_control_threads`, #1866) — **but never touches
  `self.tunnel_sources`**. The GRE local-origin threads keep their
  spawn-time `ForwardingState` clone forever.

### Concrete observable failures (all verified reachable by Codex + AGY round 1, with zero id changes)

| # | Operation | Stale behavior until daemon restart / full binding reconcile |
|---|-----------|---------------------------------------------------------------|
| F1 | Edit GRE `destination`/`source`/`key` and commit | Local-origin thread keeps encapsulating with the OLD endpoint row (frozen `forwarding.tunnel_endpoints`); transit traffic through workers uses the NEW one — split-brain per direction-of-origin. Affects all locally-originated traffic routed into the tunnel (firewall-sourced pings, routing-protocol adjacencies over the tunnel). NOTE: GRE keepalives do NOT ride this path — they probe the outer destination via the underlay (`pkg/routing/tunnel.go:304,567,615`). |
| F2 | Underlay route change (next-hop for the GRE outer destination moves) | `resolve_tunnel_forwarding_resolution` (`tunnel.rs:163`, `forwarding/mod.rs:1524-1540`) resolves against the frozen route table → old `tx_ifindex`/next-hop; either mis-egressed encap or `no_live_binding_for_tx_ifindex` exceptions. Workers (transit) follow the new route — local-origin diverges. |
| F3 | ADD a GRE tunnel at runtime | Go creates the persistent TUN anchor (`tunnel.go:124`), routes point at it, but no reader thread exists and `local_tunnel_deliveries` has no entry → local-origin blackhole AND inbound decapped-to-local delivery drop (`tx/dispatch/slow_path.rs:157-198` lookup miss falls to the #1873 R-C blanket gate → DROP). |
| F4 | REMOVE a GRE tunnel at runtime | Thread keeps the TUN fd and keeps encapsulating against the frozen state — ghost tunnel traffic on the wire. (Whether the Go-side LinkDel makes reads fail fatally is errno-dependent; the fix does not rely on it — the prune is deterministic.) |
| F5 | CoS / shaping / owner-RG config change | Local-origin path classifies + polices + owner-RG-stamps sessions (`tunnel.rs:197,220-226`) against frozen CoS/RG state. |
| F6 | Thread death (TUN open failure at bring-up race, panic, fatal io error) | Permanently dead until restart — `supervisor.rs:42`: "that tunnel's local-origin packet stream stops". No respawn exists today. |

## 3. Honest scope/value framing

This is a **correctness** fix on a cold path, not a perf win. The GRE
local-origin path carries locally-originated traffic only — single-
digit pps in normal operation. The value:

- config commits touching tunnels/routes take effect on the
  local-origin path without a daemon restart (Junos parity — vSRX
  does not need a reboot to change a GRE destination);
- runtime add/remove of GRE tunnels works at all (F3/F4);
- **revocation correctness**: after an operator points a tunnel away
  from a decommissioned/compromised peer, today's thread keeps
  sending locally-originated traffic to the FORMER destination until
  restart (AGY round-1 Q7). Not an arbitrary-party mis-encap (the
  old peer was configured moments earlier), but revocation taking
  effect only at restart is security-relevant;
- self-heal for dead local-origin threads (F6) falls out of adopting
  the #1866 entry/tombstone machinery.

If reviewers conclude the fix is not worth the churn, PLAN-KILL is an
acceptable verdict — but this is a filed, verified bug (AGY #1873
round-1 Finding 3, ratified by all reviewers; F1-F6 re-verified
independently by Codex and AGY in round 1 here), not a speculative
perf issue; the kill bar is "the design is wrong", not "the win is
small".

## 4. What's already shipped / composes with this

- **#1873 (PR #1882)**: stable content-derived tunnel-endpoint ids;
  per-packet owner check in the encap builders (`gre.rs:306-317`);
  R-D purge of remapped/removed ids; R-C blanket slow-path tunnel
  gate. The id component of the captured state is no longer the
  hazard — what remains is exactly this thread-lifecycle +
  frozen-snapshot defect. **Limit (Codex round 1)**: the owner check
  compares the endpoint row to the resolution derived from the SAME
  loaded state — it cannot detect that the READING THREAD is
  attached to the wrong TUN. §D.1b closes that.
- **#1866 (PR #1872)**: the WG control-thread three-pass reconcile
  (finished-sweep → tombstone / stale-prune on identity+attachment /
  spawn with `WG_SPAWN_BACKOFF_NS` backoff), `WgControlEntry`
  (`types/runtime.rs:55`), periodic tombstone-only liveness
  (`reconcile_wg_control_liveness`, called from `refresh_status`,
  `server/helpers.rs:27`), disarmed-stop semantics, and the
  defer-workers narrow prune. The proven template.
- **#1188**: `load_arc_if_changed` (`worker/mod.rs:1054`) — the
  established per-tick ArcSwap refresh pattern.
- `self.ha.forwarding: Arc<ArcSwap<ForwardingState>>`
  (`ha_state.rs:14`) is already stored on every path that installs
  new forwarding state: `refresh_runtime_snapshot_inner`
  (mod.rs:1156), the reconcile snapshot path, and
  `refresh_fabric_links` (mod.rs:993). A thread holding this handle
  can never observe a staler state than the workers do.

## 5. Concrete design

### Design space (paths considered)

- **Path A — per-iteration ArcSwap re-load in the thread loop.**
  Fixes F1/F2/F5 completely. Does NOT fix F3/F4/F6 (thread-set
  membership). Insufficient alone.
- **Path B — coordinator pushes state-update commands to the threads
  (WorkerCommand pattern).** Wrong shape: these threads do not drain
  command queues today; a bespoke channel per thread duplicates what
  the ArcSwap already provides, with strictly more code and an
  ordering hazard (command queue vs already-published state).
  Rejected.
- **Path C — restart all GRE threads on every refresh.** Heavy:
  every commit would close/reopen every tunnel TUN fd, dropping
  in-flight local-origin packets and briefly leaving the TUN
  readerless, plus serial stop+join on the control-socket thread per
  commit. Still needs add/remove logic anyway. Rejected as the
  general mechanism (restart remains the targeted remedy for
  attachment changes only).
- **Path D (RECOMMENDED) — A + the #1866 three-pass reconcile for the
  thread SET + a thread-side rotation gate.** Live threads track
  state through the ArcSwap (no restart on content/route/CoS
  changes); the thread set is reconciled on every
  `refresh_runtime_snapshot` (and bring-up) with tombstone+backoff
  and periodic liveness, restarting a thread ONLY when its TUN
  attachment identity changes; the rotation gate makes the
  store-to-prune window safe by construction.

### D.1 — Thread state via ArcSwap (Path A component)

`local_tunnel_source_loop` (`afxdp/tunnel.rs:19`) signature change:

```rust
pub(super) fn local_tunnel_source_loop(
    tunnel_name: String,
    tunnel_endpoint_id: u16,
    spawned_logical_ifindex: i32,
    shared_forwarding: Arc<ArcSwap<ForwardingState>>,   // was: forwarding: ForwardingState
    ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    ...
) {
    ...
    let mut forwarding: Arc<ForwardingState> = shared_forwarding.load_full();
    let mut endpoint_attached = endpoint_attachment_valid(
        &forwarding, tunnel_endpoint_id, spawned_logical_ifindex, &tunnel_name);
    while !stop.load(Ordering::Relaxed) {
        if let Some(new) = load_arc_if_changed(&forwarding, &shared_forwarding) {
            forwarding = new;
            endpoint_attached = endpoint_attachment_valid(
                &forwarding, tunnel_endpoint_id, spawned_logical_ifindex, &tunnel_name);
        }
        let ha_runtime = ha_state.load();   // once per iteration (AGY r1 R1)
        // delivery drain (with stop check, §D.2) + tun.read +
        //   if endpoint_attached {
        //       build_local_origin_tunnel_tx_request(packet, tunnel_endpoint_id,
        //           &forwarding, &ha_runtime, ...)
        //   } else { /* park: drop + debug_log, no build */ }
    }
}
```

- **One load point per source per outer iteration, at the top.** The
  same `forwarding` Arc and the same loaded HA map are used for the
  WHOLE packet build (resolution → session entry → reverse entry →
  CoS → encap). Coherence claim (narrowed per Codex r1 M3): the
  build is coherent **within each source** — one ForwardingState,
  one HA map per iteration. Cross-source atomicity between
  forwarding and HA is NOT claimed; they are published independently
  by design (`coordinator/ha.rs:39`) and the worker path has the
  same property.
- `build_local_origin_tunnel_tx_request` signature changes to take
  the loaded HA map (`&BTreeMap<i32, HAGroupRuntime>`) instead of
  `&Arc<ArcSwap<...>>`, removing today's double-load
  (`tunnel.rs:159` via `enforce_ha_resolution_at`
  `forwarding/mod.rs:539-546`, and `tunnel.rs:212-215` reverse-entry
  synthesis). Internal `pub(super)` fn — call sites are the loop +
  unit tests.
- Hot-path cost: one `ArcSwap::load` + `ptr_eq` for forwarding and
  one HA load per iteration. Each iteration already performs at
  least one `read(2)` syscall (and sleeps 1ms when idle; ≤1000
  idle iterations/s); this is the #1188 worker pattern on a
  syscall-paced single-digit-pps path. The per-BATCH hot-path rule
  is satisfied: an iteration IS the batch here (≤1 packet), and the
  AF_XDP worker hot path is untouched. Carry this justification into
  the code comment.
- Removes the per-thread full `ForwardingState` clone at spawn.

### D.1b — Rotation gate (closes Codex r1 MAJOR 1: store-before-prune window)

The reconcile (D.3) runs AFTER `self.forwarding = new_forwarding` and
`ha.forwarding.store(...)` (WG-parity ordering). In that window a
thread whose endpoint was removed, mode-flipped (gre→wireguard under
the SAME name-derived id — reachable because ids are name-only,
`pkg/config/tunnelid.go`, and WG rows hydrate without GRE src/dst,
`forwarding_build/tunnels.rs:20-30`), or reattached would load the
NEW state while still reading the OLD TUN. The #1873 owner check
(`gre.rs:306-317`) compares the new endpoint row against the new
resolution — internally consistent — so it cannot catch this.

Gate: `endpoint_attachment_valid(forwarding, id, spawned_ifindex,
spawned_name)` =

```text
forwarding.tunnel_endpoints.get(id) is Some(ep)
  ∧ ep.mode ∈ {"gre", "ip6gre"}
  ∧ ep.logical_ifindex == spawned_ifindex
  ∧ forwarding.ifindex_to_name.get(ep.logical_ifindex) == Some(spawned_name)
```

Recomputed ONLY when the forwarding Arc rotates (the
`load_arc_if_changed` Some-branch) — zero cost in steady state. While
false, the thread PARKS: it still drains deliveries (writes to its
TUN are harmless-to-stale and keep the channel from backing up until
unpublish) and still reads the TUN, but drops packets without
building (debug_log reason `local_tunnel_unattached`). It does NOT
self-exit (Codex r1 Q6: lifecycle stays single-owner in the
coordinator; the prune joins it). This also hardens the
defer-workers window beyond the narrow prune.

### D.2 — Thread-set reconcile (the #1866 three-pass, GRE flavor)

New entry type (mirrors `WgControlEntry`, `types/runtime.rs:55`,
minus the engine pointer — GRE has no engine; content changes flow
through the ArcSwap and need no restart):

```rust
/// #1881: lifecycle entry for one GRE local-origin thread, keyed by
/// tunnel_endpoint_id in `Coordinator::tunnel_sources`.
pub(crate) struct LocalTunnelSourceEntry {
    /// Live (or finished-but-unswept) handle. `None` = tombstone.
    pub(in crate::afxdp) handle: Option<LocalTunnelSourceHandle>,
    /// TUN attachment captured at spawn. Attachment drift ⇒ stale
    /// (the TUN fd is bound to the netdev).
    pub(in crate::afxdp) spawned_ifindex: i32,
    pub(in crate::afxdp) spawned_tunnel_name: String,
    /// Delivery sender for the CURRENT spawn attempt. A fresh
    /// channel pair is created per spawn (the Receiver dies with the
    /// thread); a failed spawn's sender is never published; only
    /// entries with `handle.is_some()` are published (SMR-2/AGY R2).
    pub(in crate::afxdp) delivery_tx: Option<SyncSender<Vec<u8>>>,
    pub(in crate::afxdp) last_spawn_attempt_ns: u64,
}
```

`Coordinator::tunnel_sources` becomes
`BTreeMap<u16, LocalTunnelSourceEntry>`.

`spawn_local_tunnel_sources` is rewritten as
`reconcile_local_tunnel_sources` with the three #1866 passes and the
delivery-map publication discipline (Codex r1 MAJOR 2):

1. **Finished sweep** — entry whose thread `is_finished()` → join +
   tombstone (keep attachment identity + backoff stamp; clear
   `delivery_tx`).
2. **Stale prune** — against the CURRENT `self.forwarding`, an entry
   is stale when:
   - id absent from `tunnel_endpoints`, or `mode` no longer
     `"gre"`/`"ip6gre"` → `removed` / `mode_changed`;
   - `logical_ifindex` or resolved name differs from `spawned_*` →
     `attachment_changed` (restart is the only remedy — the TUN fd
     is bound to the old netdev).
   Content changes (destination/source/key, routes, CoS) are
   deliberately NOT stale conditions — D.1 handles them in-place.
   **Ordering within the pass**: first **unpublish** — store the
   delivery map REBUILT WITHOUT the stale entries (store #1) — then
   stop+join each stale thread, then remove the entries. Unpublish-
   before-join bounds the join: workers loading the map after store
   #1 cannot enqueue into a pruned thread's channel, and the drain
   loop's new stop check (below) breaks out even if the queue was
   full at stop time.
3. **Spawn** — desired ids (mode gre/ip6gre with a resolvable name)
   with no entry (new: immediate) or a tombstone past the backoff
   (reuse the `WG_SPAWN_BACKOFF_NS` value via a shared/renamed
   constant). A failed `spawn_supervised_aux` records a tombstone
   with the attempt stamped, like `spawn_one_wg_control_thread`
   (mod.rs:760-837). Fresh `mpsc::sync_channel` per attempt.
   **Gate (SMR-1)**: this pass runs only when
   `!self.workers.handles.is_empty()` — the deferred same-plan
   window (`defer_workers` true→true reaches
   `refresh_runtime_snapshot` with zero workers) must not spawn
   threads that would freeze EMPTY `live`/`identities`/
   `worker_commands` captures. WG has no such gate on purpose (no
   binding dependency); document the asymmetry at the gate.

After pass 3, **publish the final delivery map once** (store #2):
rebuild from entries with a live handle only. Two stores per
reconcile that changes the set; zero stores when nothing changed
(skip both stores if no entry was added/removed/restarted).

**Drain-loop stop check** (`tunnel.rs:53-70`): the delivery-drain
inner loop gains `if stop.load(Ordering::Relaxed) { return; }` (or
breaks to the outer check) per chunk, so a producer that keeps the
queue non-empty cannot extend the join beyond one bounded iteration
(Codex r1 MAJOR 2: today the loop drains to `Empty`/`Disconnected`
only, and `LOCAL_TUNNEL_DELIVERY_QUEUE_DEPTH` is large enough to
sustain the race).

**Lifecycle log lines** use a distinct prefix
(`xpf-userspace-dp: GRE local-origin thread ...` spawn/stop/tombstone
with endpoint id + tun name + reason) so journald diagnostics never
conflate them with WG control lines (AGY R4).

### D.3 — Call sites

- `reconcile/bringup.rs:445`: `spawn_local_tunnel_sources()` →
  `reconcile_local_tunnel_sources()` (bring-up starts from an empty
  map after `stop_inner`, so the reconcile degenerates to pure spawn;
  workers exist at this point so the SMR-1 gate is satisfied —
  bring-up behavior unchanged).
- `refresh_runtime_snapshot_inner` (mod.rs:1158-1168): alongside the
  existing WG pair, AFTER `self.forwarding = new_forwarding` and
  AFTER `ha.forwarding.store(...)` (same position as the WG
  reconcile, so pass-2/3 decisions and a fresh thread's first
  `load_full()` see the new state; the D.1b gate covers the
  store-to-join window):
  - armed leg: `reconcile_local_tunnel_sources()`;
  - disarmed leg: `stop_all_local_tunnel_sources("disarmed")` —
    mirrors WG (#1866 Codex code-r2 rule): a disarmed helper must
    not hold TUN reader fds; in practice a no-op (threads are gone
    via `reconcile_status_bindings → stop()`), kept for race-proof
    symmetry.
- `stop_inner` (mod.rs:368-378): unchanged semantics — stop + join +
  clear ALL entries (including tombstones), store empty delivery
  map. Adjust for the new entry type (and add the drain stop check's
  benefit: bounded joins here too).
- **Defer-workers narrow prune** (mirrors #1866 Change 2b): on the
  NOT-same-plan + defer_workers branch
  (`server/handlers/snapshot.rs:~118`), add
  `prune_local_tunnel_sources_for_snapshot(&snapshot)`: stop + join
  + remove entries whose id is absent from, or no longer gre/ip6gre
  in, the new snapshot — unpublish-before-join discipline included —
  and republish the delivery map. No spawn, no forwarding mutation.
  Rationale: the Go side deletes the tunnel netdev at commit;
  holding a reader fd across the defer window relies on
  errno-dependent fatal-read behavior, while the prune is
  deterministic (AGY r1 Q4; also releases the netdev promptly for
  kernel-side reclamation).
- **Periodic liveness** (mirrors `reconcile_wg_control_liveness`,
  `server/helpers.rs:27` call site): tombstone-only, ≤1 spawn
  attempt per invocation, and it **republishes the delivery map**
  whenever the sweep tombstoned an entry or the respawn succeeded
  (Codex R3/SMR-3 — otherwise F6 respawn restores the reader but not
  inbound delivery). Coherence gate (AGY R3, GRE flavor): the latest
  stored snapshot must contain a row for the id with `ifindex > 0`,
  mode gre/ip6gre, and ifindex+linux-name matching the forwarding
  endpoint the spawn would use. Endpoint CONTENT (dst/src/key) is
  NOT part of the gate: unlike WG (whose thread binds a port and
  owns an engine), a GRE respawn bakes in nothing but the
  attachment — content always flows through the ArcSwap, so a
  content mismatch between snapshot and forwarding cannot make the
  spawned thread wrong, only the attachment can.

### D.4 — What deliberately does NOT change

- `build_local_origin_tunnel_tx_request` body semantics (signature
  gains the loaded HA map per §D.1; resolution/encap logic
  untouched).
- `live`/`identities`/`worker_commands` capture semantics (binding-
  plan-scoped; full reconcile already restarts these threads).
- WG control thread machinery (shared helpers may be extracted only
  where mechanical).
- The legacy eBPF path.

## 6. Public API preservation

- No control-socket protocol changes; no Go-side changes required.
- `Coordinator` public surface: `refresh_runtime_snapshot`,
  `refresh_runtime_snapshot_disarmed`, `stop`, status structs —
  unchanged signatures.
- `local_tunnel_source_loop`, `build_local_origin_tunnel_tx_request`,
  `spawn_local_tunnel_sources` are `pub(super)`/private — internal
  churn only.
- `recent_exceptions` reason strings preserved; new lifecycle log
  lines use the distinct GRE prefix (§D.2).

## 7. Hidden invariants the change must preserve

1. **Per-iteration, per-source coherence**: one forwarding Arc + one
   loaded HA map per outer iteration, used for the entire packet
   build. Never reload mid-packet. Cross-source (forwarding↔HA)
   atomicity is not claimed (matches the worker path).
2. **Rotation-gate before build** (D.1b): a thread whose loaded
   state no longer describes its captured attachment must not build
   — this is the correctness boundary for the store-to-join window;
   the coordinator prune is cleanup, not the boundary (the same
   boundary-vs-cleanup discipline as #1873 R-D).
3. **Unpublish-before-join, publish-live-only**: store #1 (minus
   stale) precedes stop+join; store #2 (live handles only) follows
   spawns; tombstones and failed spawns never have published
   senders. Workers' `Disconnected` tolerance
   (`slow_path.rs:184-196`) covers the residual race of a map Arc
   loaded before store #1.
4. **Drain-loop stop check**: the delivery drain must observe `stop`
   so joins are bounded under a busy producer.
5. **Stop-then-join before entry removal** (#1769/#1866 discipline):
   no mutation (session enqueue, TX enqueue) after the coordinator
   considers a thread gone.
6. **Control-socket contention** (CLAUDE.md): reconcile runs on the
   control-socket thread under the state guard, same as WG; joins
   bounded (≤ ~1 iteration: ≤1ms idle sleep / 50ms error sleep /
   one bounded packet build + drain chunk). No new high-frequency
   callers.
7. **Backoff retention**: tombstone backoff stamps survive the
   finished sweep and are reset only by removal (#1866 D1 rule).
8. **Disarmed helper must not spawn** (not even transiently): only
   the armed leg reconciles; disarmed leg stops.
9. **Spawn requires live workers** (SMR-1): never freeze empty
   binding captures; document the WG asymmetry.
10. **#1873 R-D purge interplay**: purge runs before the forwarding
    swap; the GRE reconcile after the store; in-flight last packets
    of a pruned thread were built against the OLD coherent state
    (wrong-but-well-formed for the old config) and replies hit the
    purged session table (Codex r1 verified this ordering safe).
11. **No allocation regressions on the worker hot path**: workers
    untouched except reading the same ArcSwaps they already read.
12. **HA**: owner-RG stamping of local-origin sessions now follows
    refreshed state (strictly more correct); no session-sync wire
    format change.

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | **MED** | Thread lifecycle changes on every commit path (same-plan, deferred, disarmed, bring-up). Mitigated: copies a quad-reviewed, live-validated pattern (#1866); degenerates to pure spawn at bring-up; rotation gate is fail-closed (park = drop, never mis-encap). |
| Lifetime / borrow-checker | **LOW** | All shared state is `Arc`; the entry owns its per-attempt sender; no new borrows across the spawn closure. |
| Performance regression | **LOW** | One forwarding load (ptr_eq-guarded) + one HA load per iteration on a syscall-paced ≤kpps path; workers untouched; one fewer full `ForwardingState` clone per tunnel. |
| Architectural mismatch | **LOW** | Converges GRE threads onto the SAME lifecycle architecture as WG and the SAME state-distribution mechanism as workers. |

## 9. Test plan

Deterministic pins (Rust, `userspace-dp`; the lifecycle pins follow
the `wg1866_*` pattern, `coordinator/tests.rs:2130+`, which proves
entry/tombstone lifecycle is testable without privileges — `open_tun`
failure in tests still records entries/tombstones):

1. **Staleness pin (the bug)** — written to FAIL on current master
   and pass with the fix: apply a refreshed snapshot whose GRE
   endpoint destination (or underlay route) changed with an
   unchanged binding plan; assert the state handle the local-origin
   path consumes exposes the new endpoint row/route (master: frozen
   clone keeps the old one). Unit-level companion:
   `build_local_origin_tunnel_tx_request` against pre- vs
   post-rotation Arcs yields old vs new egress/encap.
2. **Thread-set reconcile pins**:
   - add endpoint via refresh → entry appears + delivery map gains
     the key (live spawn) or stays absent (failed spawn tombstone —
     assert NOT published);
   - remove endpoint via refresh → unpublish-then-join ordering
     observable (entry gone, map key gone);
   - same-id attachment change (ifindex or name) →
     `attachment_changed` restart (Codex R5);
   - same-id mode flip gre→wireguard → GRE entry pruned, WG pass
     owns the id (Codex R5);
   - destination-only edit (same id, same attachment) → entry
     PRESERVED — no TUN churn;
   - tombstone backoff + periodic-liveness respawn coherence gate
     (existence/mode/attachment; content mismatch does NOT block);
   - liveness sweep/respawn republishes the delivery map (Codex R5);
   - disarmed refresh → all entries stopped;
   - defer-workers apply with a removed tunnel → narrow prune fires;
   - deferred same-plan window (no workers) → spawn pass does
     nothing (SMR-1 gate).
3. **Rotation gate**: with a live-thread-equivalent state (unit test
   on `endpoint_attachment_valid` + a loop-level test if
   practicable), removed/mode-flipped/reattached ids park (drop, no
   build); restored attachment un-parks.
4. **Drain stop latency** (Codex R5): a producer keeping the
   delivery queue non-empty; assert stop→join completes bounded
   (the drain loop observes `stop`).
5. **Sweep/no-resurrection**: after `stop_inner`, a liveness sweep
   creates nothing.

Gates (unmasked, before every push): `cargo build --release`; full
`cargo test --release` aggregated over all "test result" lines (known
flakes standalone-proven 5×); `go test ./...`; echo $? each. Never
`cargo fmt` on focused changes.

Live validation (loss userspace cluster, lock protocol,
`test/incus/with-cluster.sh`): configure a GRE tunnel with a
reachable underlay peer; from the firewall, run continuous ping
through `gr-X` (local-origin path); then (a) commit a destination
change and observe (tcpdump on the WAN side) the encap target switch
WITHOUT daemon restart; (b) commit an underlay route change and
observe the egress move; (c) add a second GRE tunnel at runtime and
show local-origin traffic flows immediately; (d) delete it and show
the thread stops (journal log line + no ghost encap). Re-apply CoS
after any deploy (`./test/incus/apply-cos-config.sh`).

## 10. Out of scope (explicitly)

- WG control threads (done in #1866) beyond mechanical helper
  extraction; the worker path's independent HA-vs-forwarding load
  timing (pre-existing, by design).
- The slow-path reinjection gate and session purge semantics (#1873
  R-C/R-D — shipped).
- ipip/other tunnel modes with no local-origin thread today.
- Making tunnel interfaces part of the binding plan (would force
  full worker reconciles on tunnel edits — strictly worse).
- A status surface for aux-thread liveness (tombstone map makes it
  cheap later — follow-up).
- Go-side tunnel netdev lifecycle (`pkg/routing/tunnel.go`).

## 11. Open questions for adversarial review (round 2)

Round-1 Q1-Q7 are resolved (Q1 per-iteration load ratified by both;
Q2 closed — `(logical_ifindex, name)` is sound, recovery for an
instant same-ifindex re-create is fatal-read → sweep → backoff
respawn, bounded by backoff + the 1/s liveness tick, no fd-generation
check; Q3 disarmed stop ratified; Q4 defer-prune ratified as needed;
Q5 Disconnected tolerance ratified; Q6 no self-exit ratified, with
the D.1b park replacing self-exit; Q7 severity = revocation-staleness
+ operational correctness, residual same-id window closed by D.1b).

New questions for round 2 (each an invitation to PLAN-KILL):

1. **Is the D.1b park sufficient while UNPARKED deliveries still
   flow?** A parked thread still drains and writes deliveries to its
   (old) TUN until unpublish — is writing a decapped inner packet to
   a stale-attachment TUN ever harmful (vs. merely stale), given the
   kernel routes whatever exits that TUN? If reviewers find a
   harmful trace, the park must also stop delivery WRITES.
2. **Two-store reconcile**: is the unpublish(store #1)/republish
   (store #2) pair acceptable, or does a worker that loaded the map
   between the stores and holds it across a long batch need anything
   stronger? (Claim: no — Disconnected tolerance + fresh load per
   packet at `slow_path.rs:159-162`.)
3. **SMR-1 gate edge**: with workers present but a binding partially
   unregistered (sparse worker ids), is `handles.is_empty()` the
   right predicate, or should the gate mirror whatever bring-up
   guarantees about `live`/`identities` population?
4. **Rotation-gate cost honesty**: `endpoint_attachment_valid` does
   two BTreeMap lookups + a string compare, but only on Arc
   rotation (config applies). Any objection?
5. **Anything still missed in the failure matrix** — e.g. RG-promote
   path (`queue_warm_pass(force=true)` caller) or
   `refresh_fabric_links` interactions with the rotation gate?
