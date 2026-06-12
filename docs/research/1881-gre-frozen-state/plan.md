# #1881 — GRE local-origin threads run on a frozen ForwardingState across refresh_runtime_snapshot

## 1. Status

DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR).

## 2. Issue framing

`spawn_local_tunnel_sources` (`userspace-dp/src/afxdp/coordinator/mod.rs:524`)
runs only from worker bring-up (`reconcile/bringup.rs:445`). Each GRE
local-origin thread captures, at spawn time:

- `let forwarding = self.forwarding.clone();` — a **frozen by-value
  clone** of the entire `ForwardingState` (mod.rs:540), passed to
  `local_tunnel_source_loop` (`afxdp/tunnel.rs:19`) as
  `forwarding: ForwardingState` and used per packet by
  `build_local_origin_tunnel_tx_request` (routes, tunnel endpoint
  rows, neighbors-adjacent state, zones, CoS config, owner-RG map).
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

### Concrete observable failures (all reachable with zero id changes)

| # | Operation | Stale behavior until daemon restart / full binding reconcile |
|---|-----------|---------------------------------------------------------------|
| F1 | Edit GRE `destination`/`source`/`key` and commit | Local-origin thread keeps encapsulating with the OLD endpoint row (frozen `forwarding.tunnel_endpoints`); transit traffic through workers uses the NEW one — split-brain per direction-of-origin. GRE keepalives (`pkg/routing/tunnel.go` keepaliveRunner) ride this path → false keepalive state. |
| F2 | Underlay route change (next-hop for the GRE outer destination moves) | `resolve_tunnel_forwarding_resolution` resolves against the frozen route table → old `tx_ifindex`/next-hop; either mis-egressed encap or `no_live_binding_for_tx_ifindex` exceptions. Workers (transit) follow the new route — local-origin diverges. |
| F3 | ADD a GRE tunnel at runtime | Go creates the persistent TUN anchor (`tunnel.go:124`), routes point at it, but no reader thread exists and `local_tunnel_deliveries` has no entry → local-origin blackhole AND inbound decapped-to-local delivery drop (`tx/dispatch/mod.rs:229` lookup miss). |
| F4 | REMOVE a GRE tunnel at runtime | Thread keeps the TUN fd and keeps encapsulating against the frozen state — ghost tunnel traffic on the wire (until the Go-side LinkDel makes TUN reads fail fatally, which is not guaranteed promptly). |
| F5 | CoS / shaping / owner-RG config change | Local-origin path classifies + polices + owner-RG-stamps sessions against frozen CoS/RG state. |
| F6 | Thread death (TUN open failure at bring-up race, panic, fatal io error) | Permanently dead until restart — `supervisor.rs:42`: "that tunnel's local-origin packet stream stops". No respawn exists today. |

## 3. Honest scope/value framing

This is a **correctness** fix on a cold path, not a perf win. The GRE
local-origin path carries locally-originated traffic only (pings from
the firewall, routing protocol packets over the tunnel, GRE
keepalives) — single-digit pps in normal operation. The value is:

- config commits touching tunnels/routes actually take effect on the
  local-origin path without a daemon restart (operator-visible
  correctness; Junos parity — vSRX does not need a reboot to change a
  GRE destination);
- runtime add/remove of GRE tunnels works at all (F3/F4);
- self-heal for dead local-origin threads (F6) falls out of adopting
  the #1866 entry/tombstone machinery.

If reviewers conclude the fix is not worth the churn, PLAN-KILL is an
acceptable verdict — but note this is a filed, verified bug (AGY
finding ratified by all #1873 reviewers), not a speculative perf
issue; the kill bar should be "the design is wrong", not "the win is
small".

## 4. What's already shipped / composes with this

- **#1873 (PR #1882)**: stable content-derived tunnel-endpoint ids;
  per-packet owner check in the encap builders (an id whose owning
  netdev ifindex differs from the resolution's stored one is refused);
  R-D purge of remapped/removed ids; R-C blanket slow-path tunnel
  gate. This means the **id component** of the captured state is no
  longer the hazard — what remains is exactly this thread-lifecycle +
  frozen-snapshot defect.
- **#1866 (PR #1872)**: the WG control-thread three-pass reconcile
  (finished-sweep → tombstone / stale-prune on identity+attachment /
  spawn with `WG_SPAWN_BACKOFF_NS` backoff), `WgControlEntry`
  (`types/runtime.rs:55`), periodic tombstone-only liveness
  (`reconcile_wg_control_liveness`, called from `refresh_status`,
  `server/helpers.rs:27`), disarmed-stop semantics
  (`refresh_runtime_snapshot_disarmed` → `stop_all_wg_control_threads`),
  and the defer-workers narrow prune
  (`prune_wg_control_threads_for_snapshot`). This is the proven
  template the issue's fix direction names.
- **#1188**: `load_arc_if_changed` (`worker/mod.rs:1054`) — the
  established per-tick `ArcSwap` refresh pattern (load + `Arc::ptr_eq`
  short-circuit; `load_full` clone only on rotation).
- `self.ha.forwarding: Arc<ArcSwap<ForwardingState>>`
  (`ha_state.rs:14`) is **already stored on every path that installs
  new forwarding state**: `refresh_runtime_snapshot_inner`
  (mod.rs:1156), the reconcile snapshot path
  (`reconcile/snapshot.rs:~95`), and `refresh_fabric_links`
  (mod.rs:993). A thread holding this handle can never observe a
  staler state than the workers do.

## 5. Concrete design

### Design space (paths considered)

- **Path A — per-iteration ArcSwap re-load in the thread loop.**
  Replace the frozen `forwarding: ForwardingState` parameter with
  `shared_forwarding: Arc<ArcSwap<ForwardingState>>` (a clone of
  `self.ha.forwarding`) + a cached `Arc<ForwardingState>` refreshed
  once per outer loop iteration via `load_arc_if_changed`. Fixes
  F1/F2/F5 completely. Does NOT fix F3/F4/F6 (thread-set membership).
- **Path B — coordinator pushes state-update commands to the threads
  (WorkerCommand pattern).** Wrong shape: these threads do not drain
  command queues today; a bespoke channel per thread duplicates what
  the ArcSwap already provides, with strictly more code, more
  states to test, and an ordering hazard (command queue vs the
  already-published worker-visible state). Rejected.
- **Path C — restart all GRE threads on every refresh.** Simple but
  heavy: every commit (including ones not touching tunnels) would
  close/reopen every tunnel TUN fd, dropping in-flight local-origin
  packets and briefly leaving the TUN readerless, plus serial
  stop+join on the control-socket thread per commit (control-socket
  contention budget, CLAUDE.md). Also still needs add/remove logic to
  know WHAT to restart. Rejected as the general mechanism (restart
  remains the targeted remedy for attachment changes only).
- **Path D (RECOMMENDED) — A + the #1866 three-pass reconcile for the
  thread SET.** Live threads track state through the ArcSwap (no
  restart on content/route/CoS changes); the thread set is reconciled
  on every `refresh_runtime_snapshot` (and bring-up) with
  tombstone+backoff and periodic liveness, restarting a thread ONLY
  when its TUN attachment identity changes (the TUN fd is bound to a
  netdev; no amount of state reloading can rebind it).

### D.1 — Thread state via ArcSwap (Path A component)

`local_tunnel_source_loop` (`afxdp/tunnel.rs:19`) signature change:

```rust
pub(super) fn local_tunnel_source_loop(
    tunnel_name: String,
    tunnel_endpoint_id: u16,
    shared_forwarding: Arc<ArcSwap<ForwardingState>>,   // was: forwarding: ForwardingState
    ...
) {
    ...
    let mut forwarding: Arc<ForwardingState> = shared_forwarding.load_full();
    while !stop.load(Ordering::Relaxed) {
        if let Some(new) = load_arc_if_changed(&forwarding, &shared_forwarding) {
            forwarding = new;
        }
        // delivery drain + tun.read + build_local_origin_tunnel_tx_request(
        //     packet, tunnel_endpoint_id, &forwarding, ...)  — unchanged
    }
}
```

- **One load point per outer iteration, at the top.** The same
  `Arc` is used for the WHOLE packet build (resolution → session
  entry → reverse entry → CoS → encap) — torn-state-free by
  construction; never re-load mid-packet.
- `build_local_origin_tunnel_tx_request` keeps its
  `&ForwardingState` parameter — zero churn below the loop.
- Hot-path cost: one `ArcSwap::load` + `Arc::ptr_eq` per iteration.
  Each iteration already performs at least one `read(2)` syscall on
  the TUN (and sleeps 1ms when idle); the load is noise (~1-2ns
  uncontended; this is the exact #1188 worker pattern, and an
  iteration here processes at most one packet — so this is *at most*
  one load per packet on a single-digit-pps path, and one per 1ms
  tick when idle). `load_arc_if_changed` moves from
  `worker/mod.rs:1054` to a shared location (or gets a
  `pub(in crate::afxdp)` re-export) — it is currently private to
  `worker`.
- Removes the per-thread full `ForwardingState` clone at spawn
  (memory win as a side effect; the clone is large — routes,
  policies, CoS state).
- **Fail-safe ordering bonus**: a removed endpoint's id disappears
  from the loaded state on the very next iteration —
  `resolve_tunnel_forwarding_resolution` returns a non-forward
  disposition and the packet is dropped with a reason — even
  *before* the prune pass joins the thread. Combined with the #1873
  per-packet owner check in the encap builders, stale encap is
  impossible once the new state is published.

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
    /// TUN attachment captured at spawn (ifindex + resolved name).
    /// Attachment drift ⇒ stale (the TUN fd is bound to the netdev).
    pub(in crate::afxdp) spawned_ifindex: i32,
    pub(in crate::afxdp) spawned_tunnel_name: String,
    /// Delivery sender registered in `local_tunnel_deliveries` for
    /// this thread (kept here so prune/sweep can rebuild the
    /// published delivery map without re-deriving it).
    pub(in crate::afxdp) delivery_tx: SyncSender<Vec<u8>>,
    pub(in crate::afxdp) last_spawn_attempt_ns: u64,
}
```

`Coordinator::tunnel_sources` becomes
`BTreeMap<u16, LocalTunnelSourceEntry>`.

`spawn_local_tunnel_sources` is rewritten as
`reconcile_local_tunnel_sources` with the three #1866 passes:

1. **Finished sweep** — entry whose thread `is_finished()` → join +
   tombstone (keep attachment identity + backoff stamp). Fixes F6's
   "dead forever" when combined with pass 3 + periodic liveness.
2. **Stale prune** — stop + join + REMOVE when, against the CURRENT
   `self.forwarding`:
   - id absent from `tunnel_endpoints`, or `mode` is no longer
     `"gre"`/`"ip6gre"` (covers mode flips to wireguard under the
     same name/id — the WG pass then owns that id), → `removed`;
   - `logical_ifindex` or resolved `ifindex_to_name` name differs
     from `spawned_*` → `attachment_changed` (restart is the ONLY
     remedy — the TUN fd is bound to the old netdev).
   Content changes (destination/source/key, routes, CoS) are
   deliberately NOT stale conditions — D.1 handles them in-place.
3. **Spawn** — desired ids (mode gre/ip6gre with a resolvable name)
   with no entry (new: immediate) or a tombstone past
   `LOCAL_TUNNEL_SPAWN_BACKOFF_NS` (reuse the `WG_SPAWN_BACKOFF_NS`
   value; rename or share the constant). A failed
   `spawn_supervised_aux` records a tombstone with the attempt
   stamped, exactly like `spawn_one_wg_control_thread`
   (mod.rs:760-837). The spawned closure captures the CURRENT
   `self.workers.{live,identities}` + worker command queues — valid
   because on the same-plan path the binding plan is unchanged, and
   on the bring-up path they were just built.

After any pass mutates the set, **republish the delivery map once**:
rebuild `BTreeMap<i32 /*logical_ifindex*/, SyncSender<Vec<u8>>>` from
the live entries and `self.local_tunnel_deliveries.store(Arc::new(..))`
(RCU; workers look it up per delivery via the existing ArcSwap —
`tx/dispatch/mod.rs:88`). Single store per reconcile, never
incremental tearing.

### D.3 — Call sites

- `reconcile/bringup.rs:445`: `spawn_local_tunnel_sources()` →
  `reconcile_local_tunnel_sources()` (bring-up starts from an empty
  map after `stop_inner`, so the reconcile degenerates to pure spawn
  — bring-up behavior unchanged).
- `refresh_runtime_snapshot_inner` (mod.rs:1158-1168): alongside the
  existing `spawn_wg_control_threads()` / `stop_all_wg_control_threads`
  pair, add:
  - armed (`spawn_wg == true` leg): `reconcile_local_tunnel_sources()`;
  - disarmed leg: `stop_all_local_tunnel_sources("disarmed")` —
    mirrors WG: a disarmed helper must not hold tunnel TUN reader
    fds or inject into (stopped) bindings. (Today `stop_inner` has
    already stopped them whenever the helper disarms via the
    reconcile path; the disarmed refresh leg makes it explicit and
    race-proof, same as #1866 Codex code-r2 for WG.)
  Ordering: AFTER `self.forwarding = new_forwarding` and AFTER the
  `ha.forwarding.store(...)` (same position as the WG reconcile) so
  pass-2/3 decisions and any freshly spawned thread's first
  `load_full()` both see the new state.
- `stop_inner` (mod.rs:368-378): unchanged semantics — stop + join +
  clear ALL entries (including tombstones), store empty delivery
  map. Adjust for the new entry type.
- **Defer-workers narrow prune** (mirrors #1866 Change 2b, D4): the
  NOT-same-plan + defer_workers branch
  (`server/handlers/snapshot.rs:~118`) stores the snapshot without
  reconciling. Extend `prune_wg_control_threads_for_snapshot` — or
  add a sibling `prune_local_tunnel_sources_for_snapshot` — to stop
  + join + remove GRE entries whose id is absent from (or no longer
  gre/ip6gre in) the new snapshot, and republish the delivery map.
  No spawn, no forwarding mutation. Rationale: a REMOVED tunnel's
  thread otherwise keeps a reader fd on a TUN the Go side may be
  deleting, for the whole defer window (F4's worst case).
- **Periodic liveness** (mirrors `reconcile_wg_control_liveness`,
  `server/helpers.rs:27` call site): tombstone-only, snapshot-
  coherent, ≤1 spawn attempt per invocation. Coherence gate for GRE:
  the latest stored snapshot must contain a row for the id with
  `ifindex > 0`, mode gre/ip6gre, and ifindex+linux-name matching the
  forwarding endpoint the spawn would use (the GRE analog of
  `wg_tombstone_respawn_coherent` minus the crypto identity).

### D.4 — What deliberately does NOT change

- `build_local_origin_tunnel_tx_request` body and signature
  (`&ForwardingState`).
- `live`/`identities`/`worker_commands` capture semantics (binding-
  plan-scoped; full reconcile already restarts these threads).
- WG control thread machinery (shared helpers may be extracted only
  where mechanical — e.g. the sweep loop shape; no behavior change).
- The legacy eBPF path (none of this exists there).

## 6. Public API preservation

- No control-socket protocol changes; no Go-side changes required
  (the snapshot already carries everything needed).
- `Coordinator` public surface: `refresh_runtime_snapshot`,
  `refresh_runtime_snapshot_disarmed`, `stop`, status structs —
  unchanged signatures.
- `local_tunnel_source_loop` and `spawn_local_tunnel_sources` are
  `pub(super)`/private — internal churn only.
- Status surfaces: `recent_exceptions` reasons keep their existing
  strings; new spawn/stop/sweep log lines mirror the WG wording.

## 7. Hidden invariants the change must preserve

1. **Single-load coherence**: one `ArcSwap` load per loop iteration,
   used for the entire packet build. Never reload between resolution
   and encap (torn encap = the exact bug class #1873 closed).
2. **Stop-then-join before removal** (#1769/#1866 discipline): a
   pruned thread must be JOINED before its entry (and delivery
   sender) is dropped, so no mutation (session enqueue, TX enqueue)
   can land after the coordinator considers it gone. Join latency is
   bounded: the loop checks `stop` every iteration (≤1ms sleep + one
   bounded packet build).
3. **Delivery-map publication**: workers must never observe a sender
   for a joined thread longer than one reconcile (store the rebuilt
   map AFTER the join). A send into a disconnected channel during
   the window is already handled (worker-side send error path).
4. **Control-socket contention** (CLAUDE.md): the reconcile runs on
   the control-socket thread under the state guard — same as WG
   today. Joins are bounded (≤ a few ms per stale thread; stale sets
   are tiny). No new high-frequency callers.
5. **Backoff retention**: tombstone backoff stamps survive the
   finished sweep and are reset ONLY by removal (a fresh identity
   deserves an immediate attempt) — exactly the #1866 D1 rule.
6. **Disarmed helper must not spawn** (not even transiently): the
   disarmed refresh leg stops; only the armed leg reconciles
   (#1866 Codex code-r2 rule, applied to GRE).
7. **`prior_snapshot_installed` / purge interplay (#1873 R-D)**: the
   tunnel-session purge in `refresh_runtime_snapshot_inner` runs
   BEFORE the forwarding swap; the GRE thread reconcile runs AFTER.
   A purged id's thread is pruned in the same apply; its in-flight
   last packets were built against the OLD state whose encap the
   owner check still validates — no new window opens.
8. **No allocation regressions on the worker hot path**: workers are
   untouched except for reading the same ArcSwaps they already read.
9. **HA**: owner-RG stamping of local-origin sessions now follows
   the refreshed state (today it follows the frozen one — strictly
   less correct). No session-sync wire format change.

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | **MED** | Thread lifecycle changes on every commit path (same-plan, deferred, disarmed, bring-up). Mitigated by copying a pattern (#1866) that just survived its own quad-review + live validation, and by the degenerate-to-spawn property at bring-up. |
| Lifetime / borrow-checker | **LOW** | All shared state is `Arc`; the entry struct owns its sender; no new borrows across the spawn closure. |
| Performance regression | **LOW** | One ArcSwap load per iteration on a ≤kpps path with a syscall per iteration; workers untouched; one fewer full `ForwardingState` clone per tunnel at spawn. |
| Architectural mismatch | **LOW** | This converges GRE threads onto the SAME lifecycle architecture as WG threads (reduces the number of distinct patterns by one) and onto the SAME state-distribution mechanism as workers (#1188). |

## 9. Test plan

Deterministic pins (Rust, `userspace-dp`):

1. **Staleness pin (the bug)**: coordinator-level test — install
   forwarding state with one GRE endpoint, run the reconcile, then
   apply a refreshed snapshot whose endpoint destination/route
   changed; assert the worker-visible `ha.forwarding` AND the
   thread-visible handle (same ArcSwap) expose the new endpoint row
   — and, at the loop level, a unit test that
   `build_local_origin_tunnel_tx_request` against the
   *post-rotation* `Arc` produces the new egress/encap while the
   *pre-rotation* clone (today's behavior, kept as the regression
   baseline assertion) produces the old one. This is the
   "deterministic repro first" artifact: on current master the
   loop-equivalent (frozen clone) provably keeps the old encap.
2. **Thread-set reconcile pins** (mirror the `wg1866_*` suite,
   `coordinator/tests.rs:2130-2300`, which already demonstrates this
   is testable without privileges — spawn failure still records a
   tombstone):
   - add endpoint via refresh → entry appears (live or tombstone) +
     delivery map gains the ifindex key;
   - remove endpoint via refresh → entry stopped+removed + delivery
     map loses the key;
   - rename/reattach (ifindex or name change, same id) →
     `attachment_changed` restart;
   - destination-only edit (same id, same attachment) → entry
     PRESERVED (no restart) — pins the "content changes don't churn
     TUN fds" property;
   - mode flip gre→wireguard same id → GRE entry pruned, WG entry
     owned by the WG pass;
   - tombstone backoff + periodic-liveness respawn coherence;
   - disarmed refresh → all entries stopped;
   - defer-workers apply with a removed tunnel → narrow prune fires.
3. **Sweep/no-resurrection**: after `stop_inner`, a liveness sweep
   creates nothing (mirrors `wg1866` stop test).

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

- WG control threads (done in #1866) and any refactor that merges the
  two entry types beyond mechanical helper extraction.
- The slow-path reinjection gate and session purge semantics (#1873
  R-C/R-D — shipped).
- ipip/other tunnel modes that have no local-origin thread today
  (the loop only ever spawned for gre/ip6gre; parity preserved).
- Making tunnel interfaces part of the binding plan (rejected
  alternative: it would force full worker reconciles on tunnel
  edits — strictly worse).
- A status surface for aux-thread liveness (supervisor.rs notes the
  gap; the tombstone map makes it cheap later — follow-up if
  reviewers want it).
- Go-side tunnel netdev lifecycle (`pkg/routing/tunnel.go`) —
  unchanged.

## 11. Open questions for adversarial review (each an invitation to PLAN-KILL)

1. **Is the per-iteration ArcSwap load placement right** — or should
   the reload happen only on the idle/sleep branch to keep even the
   load off the per-packet path? (Claim: per-iteration is correct —
   the worker loop does the same per tick, and deferring to idle
   would leave a saturated TUN stream stale indefinitely.)
2. **Attachment-identity definition**: is `(logical_ifindex,
   resolved name)` the complete restart condition, or can a TUN be
   re-created with the SAME name+ifindex while the old fd goes dead
   (Go anchor replace path, `tunnel.go:132-166` reuse-vs-replace)?
   If replace can recycle the ifindex, the fatal-read exit (EBADFD/
   ENODEV/ENXIO) + finished-sweep + backoff respawn is the recovery
   — is that window acceptable, or does the prune need an
   fd-generation check?
3. **Disarmed-leg stop**: is stopping GRE local-origin threads on a
   disarmed same-plan refresh ever WRONG (e.g. a brief disarm during
   ISSU where keeping the TUN reader would be preferable)? WG chose
   stop for port-release reasons; GRE holds no port — does symmetry
   justify the churn, or should disarmed simply not-spawn?
4. **Defer-workers narrow prune**: needed, or is the F4 defer-window
   exposure acceptable given the Go side deletes the netdev and the
   fatal-read path reaps the thread anyway? (WG needed it for UDP
   port conflicts; the GRE justification is weaker — reviewers
   should kill it if it's scope creep.)
5. **Delivery-channel swap race**: pass-2 restart (attachment change)
   replaces the `SyncSender` for an ifindex the workers may be
   actively sending into. Is rebuild-after-join + single store
   sufficient, or does a worker holding the OLD map Arc across a
   long batch need an explicit generation check? (Claim: send-error
   tolerance already covers it — same semantics as today's
   stop_inner empty-store.)
6. **Should the loop ALSO exit when its id disappears from the loaded
   state** (self-terminating threads) instead of relying on the
   coordinator prune? (Claim: no — single-owner lifecycle in the
   coordinator is the #1866 lesson; self-exit + sweep would race the
   prune's join-before-removal invariant.)
7. **Severity honesty check**: with #1873's owner check + R-C gate,
   is any *security-relevant* mis-encapsulation still reachable from
   the frozen state (vs. mere blackholes/staleness)? If reviewers
   find one, severity rises; if provably none, this is operational
   correctness only — does it still clear the churn bar? (We claim
   yes: F1-F4 are routine operator actions that today require a
   restart.)
