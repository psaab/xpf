# userspace-dp/src/afxdp/coordinator/

The single owner of cross-worker state and lifecycle. Constructs the
binding plan, spawns workers under the supervisor, holds the shared
BPF map handles and HA snapshot, and exposes the operator-facing
status surface to `server/` for the daemon's gRPC / HTTP queries.

This is the orchestration layer that sits *above* the per-worker
dataplane: workers take ownership of an AF_XDP socket and a
binding's hot path (see `worker/`); the coordinator owns everything
the workers share.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | `Coordinator` struct + worker-spawn + reconcile entry. The per-worker spawn closure (in `reconcile/bringup.rs`) launches `worker_loop` via 5 typed bundles (#6241): `WorkerSharedDataplane::from_coord` / `WorkerCoSState::from_coord` clone the coordinator-published shared state, and the `::new` builders carry the per-worker fresh slots — behavior-preserving, no extra clone/alloc vs. the old positional call. |
| `bpf_maps.rs` | `BpfMaps` — pinned BPF map FDs (XSK map, heartbeat, session, conntrack v4/v6) opened once and shared with every worker. |
| `cos_leases.rs` | CoS runtime-map plumbing: `refresh_cos_owner_worker_map_*` / `refresh_cos_runtime_maps` (diff-and-store of the `SharedCoSState` Arcs) plus the owner-by-queue / active-shard / root- and queue-lease / exact-backlog / vtime-floor builders with their Arc-reuse match predicates, and the #710 cross-worker status aggregation used by `status.rs`. (#1890 split.) |
| `cos_state.rs` | `SharedCoSState` — Arcs that workers consult to find owner-by-queue, live owner, root/queue leases, vtime floors. |
| `ha_state.rs` | `HaState`: HA snapshot, shared fabrics, forwarding state. (RG epoch counters live on `Coordinator` itself in `mod.rs`, not here.) |
| `inject.rs` | `request inject-packet` RPC handler — synthesizes a packet against the live state, reports disposition. The operator/API-supplied `packet_length` is bounded by `MAX_INJECT_PACKET_LENGTH` (= `UMEM_FRAME_SIZE`, 4096): an injected packet is a single unfragmented frame that must fit in one UMEM frame on TX, and 4096 keeps the IPv4 total-length / IPv6 payload-length wire fields within u16. `check_inject_packet_length` REJECTS an over-max request up front (it is NOT clamped, so an API misuse / DoS attempt surfaces as an error); the 64-byte minimum still applies. The frame builders (`frame/mod.rs`) additionally clamp the allocation to the maximum and use `u16::try_from` for the wire length as a defense-in-depth backstop so a bypassed bound can never emit a wrapped on-wire length. (#2443) **#6563: `--emit-on-wire` validates the SOURCE.** The emit path runs FIB, HA and CoS/output-filter processing but never security policy, screen, or any source check — `inject.rs` referenced neither policy nor screen — so an operator-arbitrary `source_ip` went on the wire verbatim. That is a spoofing primitive rather than a diagnostic, and the usual "loopback gRPC, therefore administrator-only" bound does not hold here: #5278 establishes that any provisioned login-class shell user reaches this plane. `validate_injected_packet_tuple` now requires the source to be an address the firewall OWNS (`is_firewall_local_address` over the global `local_v4`/`local_v6` membership sets — interface host addresses plus static-NAT/DNAT externals). Global membership, not the table-scoped test `lookup_forwarding_resolution` uses to DECIDE local delivery: an address owned only in another VRF is still ours, and emitting from it is not third-party spoofing. The gate is LAST, after every structural check, so a request that is both malformed and foreign-sourced reports the structural fault. It applies to the EMIT path ONLY — `inject-packet` without `--emit-on-wire` classifies a synthetic packet and puts nothing on the wire, so it keeps its full diagnostic range including foreign sources. |
| `neighbor_manager.rs` | `NeighborManager` — sharded ARP/NDP cache + netlink monitor for incremental updates. **#5165: the monitor thread's `JoinHandle` is now retained (`monitor_join`, no longer discarded via `.ok()`) and `stop_inner` signals + JOINs it via `stop_and_join_monitor` — mirroring `resolver_join`. Joining (bounded by the monitor's 500ms `SO_RCVTIMEO`) is what enforces no-mutation-after-stop: a retired old-generation monitor blocked in `recv()` can no longer apply a queued kernel neighbor event to `dynamic` after a reconcile cleared/rebuilt the baseline. The steady-state loop also re-checks `stop` AFTER `recv()`, before mutating, as belt-and-suspenders.** **#6314: the #1636 neighbor WARMER — the third neighbor aux thread — now follows the SAME pattern (it was the pre-#5165 odd-one-out). Its `JoinHandle` is retained (`warm_join`, no longer discarded via `.ok()`), a spawn failure is now logged instead of swallowed (leaving `warm_queue`/`warm_stop`/`warm_join` all `None` so the next reconcile retries), and `stop_inner` signals `warm_stop` + drops the producer + JOINs it via `stop_and_join_warmer`. Joining (bounded by the warmer loop's 500ms recv timeout) guarantees a detached warmer can never fire a stray ARP/NDP solicit or mutate `last_probed_at` after teardown. Fail-on-revert: `neighbor_warmer_joined_at_teardown_6314`.** |
| `refresh_bindings.rs` | Per-status-poll bridge from live worker state to the operator-facing `BindingStatus`. TWO halves that MUST stay field-for-field in step: `copy_live_snapshot` (slot HAS a live worker) and `zero_unbound_slot` (slot has none — unregistered or stopped). **A field added to the copy half and forgotten in the reset half leaves an unbound slot advertising the dead worker's value.** That drifted twice: #2515 (the reset-survivor set) and #5190, which found four shared-UMEM descriptor strings (`shared_umem_mode`/`_group`/`_socket_role`/`_disabled_reason`) plus `martian_dropped` / `ipv6_ext_header_dropped` copied but never cleared — so a dead slot reported a shared-UMEM role for a socket that no longer existed and a frozen drop count next to `rx_packets == 0`. The parity is now enforced STRUCTURALLY rather than by memory: `zero_unbound_slot_clears_every_copied_field_5190` poisons every serialized field of a `BindingStatus`, drives the real `refresh_bindings` unbound branch, and asserts the result equals `BindingStatus::default()` except for the registry-owned identity fields (`slot`, `queue_id`, `worker_id`, `interface`, `ifindex`, `registered`, `armed`) — a future field added to the copy half fails it BY NAME with no one having to remember to extend the test. Also owns the monotonic worker-liveness readiness gate (#2332 / #1792): NEVER re-derive freshness from the wall-clock `last_heartbeat` here. |
| `session_manager.rs` | Cross-thread session-table state shared between coordinator, HA worker, and packet workers via `Arc<Mutex<...>>`. Holds the synced + nat + forward-wire tables together because they're written and queried as a unit. |
| `snapshot_refresh.rs` | `refresh_runtime_snapshot{,_disarmed,_inner}` (armed/disarmed same-plan snapshot-apply legs: preflight, #1873 tunnel-remap purge, forwarding swap + stores, aux-thread reconcile, CoS owner-map + warm passes) and `refresh_fabric_links`. (#1890 split.) **#5166: the CoS owner/lease maps + `ha.fabrics` are published BEFORE the `ha.runtime` worker-visible store — a live worker (loop_body loads forwarding then CoS in one tick) must never observe new queue config without its matching CoS owners/leases (else transient class blackhole / stale-rate / over-admission).** **#6592: validation + forwarding leave through ONE `RuntimeView` store, so a worker cannot pair them across generations in either direction.** **#3766: `_inner` is a FALLIBLE atomic swap — it returns `Result<(), SnapshotIntegrityError>`, builds the new forwarding state FIRST, and only then bumps `self.validation` + rotates the neighbor-manager keys + publishes; on a build integrity error nothing mutates and the error is returned so the handler fails closed (no split-brain, no persisted reject).** |
| `status.rs` | Read-side snapshots for `show ...` queries. **#5289: `recent_exceptions()` / `last_resolution()` drain the per-worker POD exception rings (#6242: one `Arc<Mutex<ExceptionEventRing>>` per worker, now on each `WorkerRuntimeRecord` in `workers.records` — was the standalone `Coordinator::worker_exception_rings` / `worker_last_resolution` maps, mirroring the also-consolidated `worker_panics`) plus the control-thread ring, format each compact `ExceptionEvent`/`ResolutionEvent` into the operator-visible `ExceptionStatus`/`PacketResolution` HERE (interface/reason/IP/zone strings + monotonic→wall-clock via a single captured `MonoWallAnchor`), and merge by timestamp. The retired inline path formatted + locked a process-global mutex on EVERY terminal packet — the cross-worker DoS closed by #5289. The record path (`disposition::record_exception`) now writes a `&'static`-reason / `Arc<str>`-interface / `Copy`-`IpAddr` / numeric-zone POD event under a per-worker mutex with a per-(reason,5-tuple) sampler; the batched `BindingLiveState` counters stay the lossless signal. #6101: the slow-path reinject-failure sites (`_rate_limited` / `_queue_full` / `_slow_path_mtu_exceeded` / `_enqueue_failed`) record via `disposition::record_exception_suffixed`, which stores a `&'static` base reason + a `&'static` suffix (new `ExceptionEvent::reason_suffix`) so the record path stays alloc-free under a reinject-failure flood — the operator text `"{reason}{suffix}"` is reconstructed byte-identically by `ExceptionEvent::reason()` on the status thread. `record_exception_owned` remains ONLY for genuinely dynamic reasons (the `cfg!(feature = "debug-log")` forward-tuple-mismatch diagnostic). The cross-worker merge/sort/cap (`recent_exceptions`/`last_resolution` across ≥2 per-worker rings + the control ring) and the bring-up insert / teardown record-drop are unit-tested in `status_tests.rs::exception_ring_merge_6101`.** The other read-side exception is `drain_session_deltas`, which mutates per-binding state. **#5290: this RPC-fallback drain is FAIR — it spreads a `budget/num_bindings` quantum across live bindings via a rotating cursor (`WorkerManager::session_delta_drain_cursor`) using the shared `session_delta::drain_session_deltas_fair` helper, instead of handing the whole budget to the first slot with an early break. A low-slot worker can no longer consume the caller-wide budget and starve higher slots during the event-stream fallback. On budget overflow (undrained deltas remain) it arms `BindingLiveState::set_delta_loss` on the residual bindings; the owning worker loop folds that latch into `SessionTable::set_delta_loss` for the existing #2442 owner-RG resync, so no delta is silently lost. The owner-RG bulk-export mirror `ha.rs::drain_session_deltas_from_live` shares the same fair helper but does NOT arm the latch (it IS the resync).** |
| `supervisor.rs` | `spawn_supervised_worker` / `spawn_supervised_aux` — catches panics, marks the worker dead on its `WorkerRuntimeAtomics`, captures a panic message into a per-worker slot. (#925 Phase 1.) |
| `tunnel_supervision.rs` | GRE local-origin + WG control-thread LIFECYCLE (three-pass reconcile, tombstone backoff, periodic liveness sweeps, defer-branch snapshot prunes — see "Aux tunnel threads" below). The thread bodies live in `wg_control/` / `afxdp/tunnel.rs`; the entry maps (`tunnel_sources`, `wg_control_threads`) stay on `Coordinator` in `mod.rs`. (#1890 split.) |
| `wg_control/` | WG datapath control-thread BODY (one supervised aux thread per `mode == "wireguard"` endpoint, kernel UDP socket + wgN TUN). `mod.rs` holds the thread entry (`wg_control_loop`) and the orchestrating `run_wg_control_loop` (socket RX burst → TUN-read burst → 1s timer arm → idle poll(2)); the fused layers are split into `mtu.rs` (pad-aware encapped-size formula + per-peer outer-MTU guard), `sock.rs` (dual-stack bind, v4-mapped send shim, #2317 outer-TOS cmsg codec, poll(2) wait layer), `attempt.rs` (#1888 S5 handshake attempt machine + keepalive emit/pace), and `dispatch.rs` (inbound type-byte dispatch with the auth-before-roam `InboundOutcome` contract + the TUN-read encap-and-send). (#6438 split; `pad_to_16` is SSOT in `afxdp/wg/mod.rs`.) |
| `worker_manager.rs` | Per-worker lifecycle and planning state. **Two key spaces:** `live` and `identities` are keyed by binding `slot`; `records` is keyed by `worker_id`. Don't conflate them. **#6242: `records: BTreeMap<u32, WorkerRuntimeRecord>` is the SINGLE per-worker runtime registry** — it consolidates the former `handles` map plus the three sibling `Coordinator` observability maps (`worker_panics` #925 / `worker_exception_rings` / `worker_last_resolution` #5289) so a worker's handle + panic slot + exception ring + last-resolution slot register and roll back as ONE unit (`records.insert` / `records.clear`). Registration is POST-spawn-success (see `reconcile/bringup.rs`), so a failed worker never has a record to unwind (the #4952 differential is structural) and `stop_and_clear` drops all four owners of every worker in one `records.clear()`. Cold-path only: the packet path holds direct `Arc` clones and never looks up a record. Also holds `session_delta_drain_cursor` (#5290), the persistent rotating cursor for the fair RPC-fallback session-delta drain. |

## Where it sits

- Above: `server/handlers/` modules call into `Coordinator::*` for every
  control-socket RPC.
- Below: spawns and manages the per-worker poll loop in `worker/`.
- Sideways: shares `BpfMaps` and `SharedCoSState` Arcs with workers.

## Aux tunnel threads (WG control + GRE local-origin)

Both families are coordinator-owned aux threads keyed by
tunnel_endpoint_id with the same three-pass lifecycle (#1866 for WG,
#1881 for GRE): finished sweep → tombstone (backoff + attachment
retained), stale prune, spawn with backoff — reconciled at bring-up
AND on every armed `refresh_runtime_snapshot` (tunnel interfaces are
excluded from the binding plan, so tunnel-only commits never reach a
full reconcile), plus a tombstone-only periodic liveness pass from
`refresh_status` and a narrow prune on the defer-workers apply leg.

Differences that matter (#1881):

- WG threads restart when the engine Arc identity OR attachment
  changes — and also on an underlay outer-MTU change (#2921) and when a
  snapshot changes whether the thread may deliver kernel-path transport
  plaintext (`kernel_transport_changed`, #9521); GRE threads restart ONLY
  on attachment drift — endpoint
  content (destination/source/key, routes, CoS) reaches the live GRE
  loop through the shared `ha.runtime` ArcSwap (one
  `load_forwarding_if_changed` per loop iteration, the #1188 pattern —
  it compares the view's NESTED forwarding Arc, so a validation-only
  publish correctly reads as no change).
- A WG thread whose listen port is not the snapshot's
  `wg_steered_listen_port` DROPS a transport record that reaches its
  socket through the kernel (counted as `rx_unsteered_transport_drops`)
  instead of writing the plaintext to its wgN TUN (#9521). The shim claims
  transport data for the steered port only, so those records never reach
  the worker, and the TUN write handed them to the kernel's forwarding
  path with no zone policy. The decision is `WgKernelTransport`, computed
  once per spawn (`wg_kernel_transport_for_endpoint`) and fail-closed: a
  snapshot naming no steered port delivers for no endpoint. The steered
  port's thread keeps delivering, per #8274's stated residual. Tests reach a
  spawned thread's packet path through the `#[cfg(test)]` TUN stand-in
  registry in `wg_control/mod.rs` (a real TUN needs CAP_NET_ADMIN).
- The GRE loop carries a rotation gate (`endpoint_attachment_valid`,
  `tunnel.rs`): on every forwarding-Arc rotation it re-validates that
  the loaded state still describes its TUN attachment (id present,
  mode gre/ip6gre, ifindex+name match) and PARKS — drops without
  building — when it does not. This closes the store-to-join window:
  the #1873 owner check compares the endpoint row against a
  resolution from the SAME loaded state and cannot detect a thread
  reading the wrong TUN.
- GRE spawn is gated on live worker handles (the deferred same-plan
  window reaches refresh with zero workers; a thread spawned there
  would freeze empty binding captures). WG has no such gate — WG
  control threads use kernel UDP+TUN and have no binding dependency.
- `local_tunnel_deliveries` publication is live-handles-only and
  follows unpublish-before-join: the stale set is removed from the
  published map BEFORE stop+join (so a busy worker producer cannot
  extend the join — the delivery drain also observes `stop` per
  chunk), with a final republish after spawns.
- #2412: the published value is a `LocalTunnelDelivery` (the mpsc
  sender PLUS an eventfd `TunnelWake`), not a bare sender. The GRE
  local-origin loop blocks in `poll(2)` on {TUN fd, eventfd} instead
  of the former 1ms `thread::sleep` busy-poll (~1000 wakeups/sec/tunnel
  when idle). The worker slow path signals the eventfd on a successful
  enqueue, and the stop/join path signals it after setting `stop`, so a
  queued delivery and a shutdown both wake the loop immediately rather
  than after the poll cap. WG control threads keep their own socket-poll
  cap and carry no eventfd (`LocalTunnelSourceHandle.wake == None`).

## Notable invariants

- **Every per-worker counter on the wire is BOUND to its own source
  (#6961).** `status.rs::worker_runtime_snapshots` maps
  `WorkerRuntimeAtomics` -> `WorkerRuntimeCounters` -> the wire
  `WorkerRuntimeStatus` through two long field-by-field literals, and
  **thirty of the fields are `u64` with the same name on both ends** —
  so substituting any one for a same-typed sibling
  (`new_flow_installs: s.session_create_drops`, two
  `cos_queue_lease_undergrant_*` transposed) compiled and reddened
  nothing. Every counter reaching gRPC and Prometheus goes through
  there, so a copy-paste reports a correct counter under a neighbour's
  series forever while every upstream counter test stays green.
  `status_mapping_6961_tests.rs` seeds each field with a **DISTINCT**
  value and drives the real `worker_runtime_snapshots`: distinctness is
  the whole mechanism, because an all-zeros or repeated-value fixture
  cannot tell `st.a = src.a` from `st.a = src.b`. It binds from the
  ATOMICS, not from the counters snapshot, so a swap in EITHER hop reds —
  though the upstream `WorkerRuntimeAtomics::snapshot()` hop was ALREADY
  guarded by `worker_runtime::tests::snapshot_roundtrip`, a distinct-value
  round-trip predating #6961 (matrix cell B1 confirms it still reds). The
  hop that was genuinely unbound is the `worker_runtime_snapshots` literal;
  covering the upstream one too is belt-and-braces, and `snapshot_roundtrip`
  must not be deleted on the strength of the new file.
  A binding test over today's fields cannot see tomorrow's, so
  `every_runtime_atomic_is_bound_or_knowingly_off_wire_6961` parses the
  struct and requires each `AtomicU64` to be bound or listed in
  `DELIBERATELY_OFF_WIRE` (the four window bases + `window_gen`, which
  are rotation bookkeeping) — the same structural discipline as #5190's
  `zero_unbound_slot_clears_every_copied_field_5190`. **Adding a counter
  here means adding it to `for_each_shared_scalar!` or to the off-wire
  list with a reason; there is no third option that compiles green.**
  Not single-sourced: the two shapes legitimately differ (wire type with
  omitempty, four source structs, the `cos_queue_lease_undergrant`
  sub-struct flattened to six scalars, the window fields renamed to
  `*_60s`), so the AGREEMENT is bound instead.

- **The worker launch boundary is 5 typed bundles, constructed via named
  builders — not a positional arg list (#6241).** The `bring_up_workers`
  spawn closure (`reconcile/bringup.rs`) builds `WorkerLaunchPlan`,
  `WorkerSharedDataplane`, `WorkerControlChannels`, `WorkerCoSState`, and
  `WorkerPublishedTelemetry` (defined in `worker/launch.rs`) and moves them
  into `worker_loop`, which destructures them back into the same locals at
  entry. Construct them ONLY via `WorkerSharedDataplane::from_coord` /
  `WorkerCoSState::from_coord` (coordinator-published state) and the `::new`
  builders (per-worker fresh slots) — NOT inline struct literals — so the
  `Arc::ptr_eq` wiring tests in `worker/launch.rs` bind the exact
  session-map (`synced`/`nat`/`forward_wire`) and heartbeat/export-ack
  silent-swap hazards the old 38-parameter positional protocol carried.
  Behavior-preserving: one `Arc::clone` per field, exactly as the old
  inline call did. **#6242 (integrated):** `recent_exceptions` /
  `last_resolution` (and the `panic` slot) are allocated ONCE, one clone
  RETAINED for the worker's `WorkerRuntimeRecord` and the original MOVED into
  `WorkerPublishedTelemetry` / `spawn_supervised_worker` — the record and the
  live worker SHARE the allocation. The record is registered as ONE
  `records.insert` POST-spawn-success, so a failed worker never publishes a
  record (the #4952 differential is structural — no pre-spawn insert, no
  spawn-Err `.remove`).
- **Reconcile progress + failure identity are a TYPED value, not a free-form
  string (#6244).** `Coordinator::last_reconcile_stage` is a
  `ReconcileStage` enum (`reconcile/stage.rs`) — one variant per progress
  step (`Idle`/`Start`/`NoSnapshot`/`Planned`/`ReplayedSynced`/`Spawned`) and
  per failure identity (`MissingPin`/`OpenMapFailed`/`SnapshotIntegrityError`
  {,`Detail`}/`SpawnWorkerFailed`/`WorkerBindIncomplete`). The legacy operator
  string is produced in exactly one place — the enum's `Display` — and is
  rendered ONLY at the `reconcile_debug` / wire `debug_reconcile_stage`
  boundary (`status.rs`) and inside `ReconcileError`'s `Display`; the strings
  are preserved byte-for-byte **except `WorkerBindIncomplete`**, which has been
  deliberately extended twice — #6245 appended the explicit per-slot causes, and
  #7497 added the NIC coordinate (`:<interface>:q<queue>`) to each cause. That
  exception is stated because "byte-for-byte" was the blanket claim and #6245
  had already made it false. Nothing parses these strings; they are operator
  diagnostics reaching the control-response error on a failed commit, so
  extending one is a legibility decision rather than a wire change.

  The #7497 extension exists because this is the LOUD failure: a bind shortfall
  is a fail-closed refusal that already surfaces, so the question was never
  whether it gets noticed but whether the operator learns enough to act. A slot
  number is a position in the minted sequence, and since per-interface queue
  planning the slot -> (interface, queue) mapping moves whenever any interface's
  queue count changes, so it could not be resolved to a NIC queue after the
  fact. The coordinate is captured through `BindingCoordinate::of` at both
  failure sites; the copy is under test, though the capture CALL still is not —
  reaching it needs a real AF_XDP bind failure. `ReconcileError::{MapSetup,WorkerSpawn,
  WorkerBindIncomplete}` carry the typed `ReconcileStage` rather than a cloned
  string, so a failure identity cannot be silently reinterpreted as informal
  success text (the #4952 overwrite class). #6244 also moved the `"stopped"`
  write OUT of `stop_inner` (which is called mid-reconcile by `tear_down` and
  by the bring-up fail path): an EXPLICIT stop records `ReconcileStage::Stopped`
  in `stop`/`stop_with_event_stream`, so a terminal failure identity is never
  clobbered by a teardown that is part of the same reconcile attempt — the
  bring-up fail path no longer needs the old overwrite-then-restore dance.
  Fail-on-revert: `reconcile_stage_renders_byte_identical_legacy_strings`.
- The coordinator is the single owner; workers hold `Arc` clones.
  Lifetime hazards from breaking that invariant are how cross-binding
  redirect designs have died historically (see `docs/per-5-tuple/state.md`).
- Worker spawn happens via the supervisor; never call
  `std::thread::spawn` directly for a worker — it bypasses the panic
  capture.
- `defer_workers=true` on `apply_snapshot` skips spawn until the next
  reconcile (used during RETH MAC programming so workers don't bind
  to an interface that's about to drop and re-add its MAC).
- **A deferred apply still runs the pre-teardown integrity build before
  ack/persist (#5171).** `defer_workers=true` skips the worker spawn but
  the snapshot is still ACKed + persisted as the boot baseline, so it must
  be fully BUILDABLE with all mandatory resources first. The disarmed
  defer path cannot borrow `reconcile` for this (with forwarding not yet
  armed, `reconcile_status_bindings` takes the disarmed STOP path — a
  teardown with no integrity build; when armed it would spawn workers,
  violating the defer contract). `Coordinator::validate_snapshot_buildable`
  (`reconcile/mod.rs`) factors out the SAME three pre-teardown legs
  `reconcile` runs — policy preflight (`preflight_policy_state`, shared
  verbatim), mandatory + present-optional map-pin openability
  (`validate_map_pins`), and the full forwarding build
  (`validate_forwarding_buildable`) — as a side-effect-free `&self` check
  (map FDs opened then dropped; scratch policy/NAT counter stores so a
  rejected snapshot leaks no handles; no teardown, no spawn, no binding
  mutation, no `last_reconcile_stage` write). The defer `apply_snapshot`
  handler runs it BEFORE the tunnel/WG prunes and the `guard.snapshot`
  swap and fails closed on error (restore the bumped status generation,
  `ok=false`, no persist). A parity test locks that validate and reconcile
  reject the identical non-buildable snapshot (no drift). Pre-#5171 the
  defer path skipped the build entirely, so a non-buildable config (bad
  interface address / CoS queue / NAT64 / NPTv6 rule, or a
  MISSING/UNOPENABLE mandatory map pin) was acked `ok=true` and persisted,
  only to fail-OPEN at the later deferred bring-up.
- **The map-pin gate is ONE opener shared by both callers (#6243).** The
  activated `preflight_map_fds` and the deferred `validate_map_pins` used
  to carry two hand-kept copies of the seven-pin contract (3 mandatory
  xsk/heartbeat/sessions + 4 optional conntrack v4/v6, dnat_table[/v6]).
  They now both route through one pure `open_snapshot_maps(&MapPins) ->
  Result<OpenedSnapshotMaps, MapPinFault>` (`reconcile/snapshot.rs`), so
  they can never drift on which snapshots pass or how a fault is
  classified. The opener is side-effect-free and returns the opened FD
  bundle; the ONLY per-caller difference is keep-vs-drop of that bundle
  (RAII — the activated path assembles it into `ReconcileSnapshotFds`, the
  deferred path `.map(|_| ())` drops it), so no `mode` parameter is
  needed. On a fault a thin COLD ADAPTER on the activated caller stamps
  `last_reconcile_stage` (from `MapPinFault::stage()` — the typed #6244
  `ReconcileStage`) plus every registered binding's `last_error` (from
  `MapPinFault::binding_error()`, which owns the byte-parity trap that the
  xsk per-binding label is uppercase `XSK` while its stage token is
  lowercase `xsk`). Unifying FIXES two latent divergences (both normalize
  the deferred path toward the activated SSOT, both stay fail-closed):
  (1) the deferred walk was ONE-pass (empty-then-open per pin) while
  activated was TWO-pass (check all mandatory emptiness first, then open),
  so a multi-fault snapshot could report a different stage from each path;
  the shared two-pass order makes them identical. (2) the deferred walk
  dropped each FD immediately, so under FD-table pressure it could PASS
  where activated (retaining all seven FDs simultaneously) FAILED; the
  shared bundle now holds every opened FD until the whole contract
  succeeds, giving the deferred path the same low-FD failure. Fail-on-
  revert: `reconcile_all_seven_pin_faults_lock_stage_and_binding_strings_6243`,
  `map_pin_faults_react_identically_activated_and_deferred_6243`,
  `multi_fault_map_pins_use_two_pass_precedence_from_both_paths_6243`,
  `both_paths_open_full_seven_pin_bundle_before_ok_6243`. (Follow-up:
  #6246's `ReconcileSnapshotFds` state-representability cleanup — no
  `default()` placeholder, non-`Option` `apply_snapshot` return — is a
  SEPARATE concern tracked on #6243, not done here.)
- **Same-plan refresh is a fail-closed atomic swap (#3766).** The
  same-plan `apply_snapshot` leg (binding plan unchanged) runs
  `refresh_runtime_snapshot{,_disarmed}` instead of a full reconcile.
  Like the full reconcile's pre-teardown `build_reconcile_forwarding`
  (#2484), it builds the new `ForwardingState` FIRST and only commits
  the observable mutations — `self.validation` bump (H2), neighbor-
  manager key rotation + stale-key delete (H3), forwarding swap, and the
  `RuntimeView` publish — AFTER the build
  succeeds. A non-policy integrity fault (invalid interface address,
  CoS queue, NAT64 / NPTv6 rule) that only the full build catches now
  returns `Err(SnapshotIntegrityError)`; the handler reports `ok=false`,
  restores the bumped status generation, and does NOT persist the
  rejected snapshot. The prior good state stays live and consistent —
  no split-brain (validation ahead of a stale forwarding table), no
  deleted-neighbor blackhole, no `ok=true` on a rejected snapshot.
  Distinct from #2484 (full-apply teardown) and #2916 (queue replan).
- **The dead-worker sweep reclaims NAT holder bits AND the CoS V_min slot
  (#7092 / #6979 / #9367).** `retire_worker_holders_where` walks every worker
  its predicate selects, under a one-shot `holders_retired` CAS, and is driven
  from the 1 Hz `refresh_status` path. It reclaims the three NAT allocator
  families for every worker the predicate selects and — since #9367 — calls
  `vacate_worker_v_min_slots` for those whose `atomics.dead` is set, releasing
  the worker's slot in every `cos.queue_vtime_floors` entry. The `dead` gate is
  load-bearing: `retire_all_worker_holders` selects `|_| true` for the #7092
  teardown reclaim and runs BEFORE `workers.stop_and_clear`, i.e. while those
  workers are still running, so an ungated vacate would race a live `publish()`
  — and it would buy nothing, because that same teardown stores an empty
  `queue_vtime_floors` a few statements later.
  Without it a PANICKED worker's frozen `queue_vtime` pins the cross-worker
  V_min indefinitely and taxes every survivor on that shared_exact queue about
  11% of drain opportunities (see `cos/README.md`). The vacate is safe from
  this thread precisely because it runs only for a worker the supervisor
  already marked `dead`: the owning writer has exited and nothing respawns it,
  so `PaddedVtimeSlot`'s single-writer contract still holds. It
  rides the same one-shot CAS rather than running per tick, so a slot index a
  LATER generation hands to a live worker is never re-cleared.
- **CoS maps are published BEFORE forwarding becomes worker-visible
  (#5166).** In the same-plan refresh the workers KEEP RUNNING (no
  teardown), so a live worker observes the coordinator's ArcSwap stores
  per tick. `worker/loop_body` loads the `RuntimeView` FIRST, then the
  CoS map Arcs (`owner_worker_by_queue` / `owner_live_by_queue` /
  `root_leases` / `exact_backlogs` / `queue_leases` / `queue_vtime_floors`),
  and rebuilds `cos_fast_interfaces` from whichever CoS maps it holds.
  The commit therefore stores the derived CoS maps
  (`refresh_cos_owner_worker_map_from_identities`) and `ha.fabrics`
  BEFORE the `ha.runtime` store. Because the worker reads
  forwarding-then-CoS in one tick and the coordinator stores
  CoS-then-forwarding, any worker that observes the new forwarding is
  guaranteed by ArcSwap acquire/release ordering to also observe the
  matching CoS maps — closing the pre-#5166 window where a worker saw the
  new queue config with a stale/empty CoS owner map (transient class
  blackhole for a newly added queue, stale-rate meter, or N-worker
  lease over-admission). The reverse window (new CoS maps visible while a
  worker still reads the old forwarding) is benign: an added queue is not
  classified-to until forwarding rotates, and a removed queue merely loses
  a dying CoS entry for one tick. This is a pure reorder of the
  coordinator-side stores — no new per-tick worker cost, no worker-side
  lock — matching the full-reconcile bring-up, which already refreshes the
  CoS maps before spawning workers. The WG/GRE aux-thread reconcile still
  runs AFTER the forwarding store (a fresh control thread's first
  `load_full()` must see the new state). A per-instance
  `#[cfg(test)] cos_owner_at_forwarding_publish` seam records the CoS
  owner map at the forwarding-publish instant so the ordering regression
  test (`refresh_runtime_snapshot_publishes_cos_owner_map_before_forwarding`)
  goes RED if the reorder is reverted. That seam captures only the owner
  map, so — unlike the #6592 seam below — it does not prove its own
  placement: hoisting the `ha.runtime` store above it would satisfy the
  assert vacuously. The other publications riding the same gate (CoS
  owner-live, root leases, exact backlogs, queue leases, vtime floors, and
  `ha.fabrics`) have no individual ordering assertion at all. Tracked as
  **#6593**.
- **Validation and forwarding are published as ONE atomic pair (#6592,
  closing #6291).** They used to be two independent `ArcSwap`s
  (`shared_validation` and `ha.forwarding`), and coherence depended on the
  coordinator storing them in one order and every worker loading them in
  the opposite one. That can only ever exclude ONE of the two torn
  orientations — an acquire/release pair is directional — so it could not
  close the defect:
  - `(old validation, new forwarding)`: a packet stamped at the OLD
    generation passes `classify_metadata` against the worker's old
    validation and is then forwarded under the NEW tables. This is what
    #6291 named, and what #6333's read-order flip excluded.
  - `(new validation, old forwarding)`: the mirror, which that flip left
    behind — and WIDENED, since it needs only the forwarding load to land
    inside the publish window rather than the whole window to nest between
    two adjacent loads. It is not drop-only. While the shim still stamps
    the OLD generation the pair merely drops
    (`ConfigGenerationMismatch`, or `FibGenerationMismatch` when only the
    FIB generation moved). But once the coordinator's reply reaches Go and
    Go writes the new generation to `userspace_ctrl`, the shim stamps NEW;
    those packets pass `classify_metadata` against the new validation and
    are forwarded under the STALE tables — a withdrawn route still
    resolves, a newly added deny is not applied.

  #6592 publishes both halves inside ONE `Arc`, `RuntimeView`
  (`types/runtime_view.rs`), stored through the single choke point
  `Coordinator::publish_runtime_view`. A worker's refresh is a single
  `ArcSwap` load, so whichever view it observes, both halves came from the
  same publish. There is no pair to tear and no ordering discipline to get
  wrong; both orientations are structurally impossible.

  **The choke point is enforced by TYPES, not convention.** The coordinator
  holds a `RuntimeViewChannel` and consumers hold a `RuntimeViewReader`
  (`types/runtime_view.rs`); both wrap the `ArcSwap` in a private field, so
  `publish` is the only mutation that exists anywhere and a consumer cannot
  obtain a writer at all. `RuntimeView` itself has private fields and is NOT
  `Clone`, so a loaded view cannot be mutated, and `RuntimeView::new` is the
  only way to obtain a view value in the tree. That combination came from a
  review probe: while `runtime_reader()` still returned the raw
  `Arc<ArcSwap<RuntimeView>>` and the view was cloneable, production code could
  clone a loaded view, bump its `fib_generation`, and store it — publishing the
  exact torn pair while every source-canary rule passed. Each of those three
  lines is now a compile error.
  `tests/runtime_view_publish_canary.rs` remains as defence in depth for the
  residue types cannot express: a new publish site inside `coordinator/`, the
  raw `ArcSwap<RuntimeView>` escaping its module again, and a second view load
  in one worker tick. For the `coordinator/` half of that claim to be true the
  canary has to actually scan this file, and a follow-up review found it did
  not: it split production from test code by truncating at the first top-level
  `#[cfg(test)]`, which in `mod.rs` sits on a test-only `use` at line 35 — so
  everything below it, choke point included, went unscanned, and a marked
  construct-and-publish added there compiled and passed the canary. It now
  tracks regions instead (skip the attributed item or its braces, keep
  scanning), with self-tests pinning that production code after a `#[cfg(test)]`
  import is still counted.

  **Holding an OLD view stays possible and is SAFE** — new-stamped packets
  mismatch the old validation and DROP, the intended fail-closed
  behaviour. The defect is an INCOHERENT pair, not a stale coherent one;
  nothing forces a refresh.

  **The forwarding half stays a NESTED `Arc` deliberately (#1188).** The
  simpler shape — inlining `ValidationState` into `ForwardingState` —
  would make `bump_fib_generation` rebuild the whole forwarding state to
  move a generation counter, and rotate the worker-visible `Arc`, dragging
  every worker through its expensive rotation branch (screen-profile and
  opening-override clones, cold-path slot rescan, input-filter session
  purges, CoS runtime reset) for a change that touched no table. Go fires
  `Manager.BumpFIBGeneration` repeatedly during route convergence
  precisely to avoid a rebuild. `republish_runtime_validation` instead
  reuses the published forwarding `Arc`, so the worker's `Arc::ptr_eq`
  short-circuit still hits. Measured by `benches/runtime_view_refresh.rs`:
  the rebuild is ~66x the `Arc` reuse at 1K routes and ~262x at 10K, while
  the per-tick worker refresh went from ~46 ns (two loads) to ~23 ns (one).

  Both halves are RED-on-revert guarded. Producer:
  `refresh_runtime_snapshot_publishes_a_coherent_view_pair` asserts the
  pair a worker observes IS the pair the choke point intended, using the
  per-instance `#[cfg(test)] runtime_view_at_publish` seam — which also
  retains the previous view so it proves its own position (hoisting the
  store above the capture goes RED). Consumer:
  `snapshot_refresh_runtime_view_pair_is_atomic_6592` (worker/loop_body)
  drives the refresh with a coordinator publish injected through the
  `between` seam and asserts the returned pair is coherent; splitting the
  refresh back into two `ArcSwap` loads goes RED in EITHER order, naming
  which orientation it reintroduced. `#1188` itself is pinned by
  `bump_fib_generation_publishes_new_stamps_without_rotating_forwarding`.
  The worker's startup seed (`worker/loop_body/setup.rs`) takes its pair
  from the same single load, and `stop_inner`'s teardown publishes the
  default pair through the same choke point (no live readers there — the
  worker threads are already joined — but one path everywhere keeps the
  rule true at every site).
- **A POST-teardown worker-spawn failure fails closed (#4952).** The
  #2440/#2484/#3789 fail-closed legs above all abort BEFORE `tear_down`,
  so the prior workers stay live. `bring_up_workers` runs AFTER teardown:
  its per-worker `spawn_supervised_worker` (→ `pthread_create`) can return
  EAGAIN/ENOMEM under resource exhaustion, and the old workers are already
  gone — a queue set left with no XSK-bound worker is a silent forwarding
  outage. Pre-#4952 `bring_up_workers` returned `()`, only LOGGED the
  failure + recorded an exception, then UNCONDITIONALLY overwrote
  `last_reconcile_stage` with `spawned:workers=..` and returned success —
  so `reconcile` returned `Ok(())`, the control handler acked `ok=true`,
  and PERSISTED the broken snapshot as the boot baseline (no retry). Now
  `bring_up_workers` returns `Result<(), WorkerBringUpError>`: on the FIRST spawn
  failure it ABORTS the remaining launches (the data plane is already
  broken; more XSK-bound workers cannot restore forwarding and only widen
  the resource pressure), PRESERVES the `spawn_worker_failed:<id>:<err>`
  stage (no `spawned:..` overwrite), skips the auxiliary-thread bring-up,
  and returns the stage. `reconcile` maps it to
  `ReconcileError::WorkerSpawn` — one of two `ReconcileError` variants
  raised AFTER teardown (`WorkerBindIncomplete` (#5143) is the other; the
  data plane HAS moved; there is no prior-state restore
  that brings the torn-down workers back, only fail-closed bookkeeping +
  a retry/last-good reconcile). Full pre-teardown preflight of the spawn is
  not tractable (a real `pthread_create` cannot be probed without spawning,
  and the old workers must free the XSK queue bindings first), so this is
  the minimal fail-closed guarantee: do not persist a known-broken
  snapshot. A per-instance `#[cfg(test)] force_worker_spawn_fail` seam
  drives the regression tests (coordinator-level
  `reconcile_post_teardown_worker_spawn_failure_fails_closed_4952` +
  handler-level `post_teardown_spawn_failure_fails_closed_no_persist_4952`).
  **#6242 makes the DIFFERENTIAL structural.** The launched workers
  `0..K-1` stay live because their `WorkerRuntimeRecord`s are registered
  ONLY on spawn-success (`records.insert` in the `Ok` arm) — the failed
  worker `K` never inserted a record, so the spawn-Err arm has NOTHING to
  unwind (the pre-#6242 three `.remove(&worker_id)` calls are gone) and
  never touches the launched records. The `force_worker_spawn_fail_skip`
  (fail the Kth, not the 1st) + `force_worker_healthy_stub` seams drive the
  PARTIAL-success test
  (`reconcile_partial_spawn_failure_preserves_launched_records_6242`), which
  asserts workers 0..K-1 keep their records and worker K has none; the
  symmetric `reconcile_bind_incomplete_clears_all_records_6242` pins the
  other side (bind-incomplete → `stop_inner` clears ALL).
- **A POST-SPAWN in-thread worker bind failure fails closed via the
  startup readiness barrier (#5143). HEARTBEAT != READINESS.** #4952 above
  catches only the SPAWN failure — the thread that never starts. But a
  worker that spawns SUCCESSFULLY can still fail its IN-THREAD XSK/UMEM
  binds inside `worker_loop_setup` (the private-binding `Err` arm records
  the failure by leaving the binding out of the worker's `bindings` vec)
  and then enter its steady loop with an EMPTY/PARTIAL binding set — yet it
  keeps HEARTBEATING, so the thread-death supervisor is satisfied and
  (pre-#5143) `bring_up_workers` returned `Ok`, the reconcile committed, and
  the handler ACKed `ok=true` + PERSISTED the snapshot: a SILENT forwarding
  outage (a queue set with a live worker but no XSK-bound binding). #4952's
  spawn-error propagation does NOT catch it (the spawn succeeded). Now each
  newly-started worker REPORTS its actual bound-slot set (a
  `WorkerStartupReport` over a per-reconcile `mpsc` channel) after its binds
  and BEFORE its steady loop; after the spawn loop `bring_up_workers` WAITS
  (bounded by `WORKER_STARTUP_BARRIER_TIMEOUT_NS` = 10s — a worker that
  never reports in time is treated as failed, it does NOT block forever) and
  requires `bound == planned` per worker. On ANY shortfall/timeout it FAILS
  CLOSED: `stop_inner(false)` STOPS + JOINS the newly-started workers (no
  leaked live-but-unbound worker), preserves the `worker_bind_incomplete:..`
  stage, and returns `WorkerBringUpError::BindIncomplete`, which `reconcile`
  maps to `ReconcileError::WorkerBindIncomplete` — the SECOND post-teardown
  `ReconcileError` variant (alongside `WorkerSpawn`), handled the same way
  by the control handler (`ok=false`, do NOT persist). `bring_up_workers`
  now returns `Result<(), WorkerBringUpError>` (was `Result<(), String>`) so
  the two post-teardown classes map to distinct variants. A per-instance
  `#[cfg(test)] force_worker_bind_incomplete` seam (spawns a joinable stub
  worker that reports a bound set short by one slot, then heartbeats until
  stopped) drives the regression tests (coordinator-level
  `post_spawn_inthread_bind_failure_fails_closed_5143` + handler-level
  `full_apply_post_spawn_inthread_bind_failure_fails_closed_no_persist_5143`).

- **What the two post-teardown failure classes leave on the REPORTED binding
  surface (#8388).** The bullets above describe the coordinator internals; what
  reaches an operator, and what the Go manager's auto-rebind wedge predicate
  (`hasBusyBindingsWedgeLocked`) reads, is the `BindingStatus` array that
  `reconcile`'s closing `refresh_bindings` writes on the failure path too. The
  two classes differ there, and the difference is load-bearing enough that #8388
  was filed against the wrong half of it:
  - **Bind-incomplete (#5143) is ALL-OR-NOTHING.** `stop_inner(false)` empties
    `workers.live`, so every slot routes through `zero_unbound_slot` and the
    reported set has ZERO bound slots — including the workers that bound their
    FULL planned set. One EBUSY on one queue is reported as a fleet-wide wedge,
    not as "one wedged binding among fifteen healthy ones". #8388 proposed a
    per-slot `rebind_slot` verb (and the per-slot worker lifecycle + per-slot
    zero-copy quiesce it would need first) to stop the global `rebind` from
    destroying those fifteen; there are none to destroy, so it was closed
    rather than built. Measured by `bind_incomplete_leaves_no_bound_sibling_8388`
    — a THREE-worker fixture, two of which bind fully; the one-worker shape
    `post_spawn_inthread_bind_failure_fails_closed_5143` uses satisfies it
    vacuously.
  - **Spawn-failure (#4952) IS partial**, by design: the arm returns without
    `stop_inner`, `workers.live` survives, and the launched workers' slots keep
    reporting bound while the unspawned worker's slots are registered, armed and
    unbound. This is the one reachable mixed shape — and what is missing at those
    slots is a worker THREAD, not a socket, so a targeted socket rebind could not
    repair it; the global rebind re-runs the whole plan and spawns the missing
    worker. Measured by `spawn_failure_does_leave_bound_siblings_8388`, which is
    also the POSITIVE CONTROL for the cell above: it proves the same instrument
    reads back a partial set when one exists, so the empty bound set in the
    bind-incomplete cell is a property of the reconcile and not of the test
    scaffolding.
  - Both cells depend on the `#[cfg(test)]` stub workers publishing
    `BindingLiveState::set_bound` for every slot they REPORT bound (the publish a
    real `worker_loop` makes from `BindingWorker::create`). Without it a
    "healthy" stub is healthy only in its startup report, `refresh_bindings`
    reads `bound = false` for it either way, and any cell over the binding
    surface is mutation-insensitive by construction.

- **The bind-failure CAUSE survives the fail-closed teardown (#8558).** The
  bullet above establishes that a bind failure reports every slot unbound. What
  it did NOT report was WHY. `stop_inner(false)` empties `workers.live`, so
  `refresh_bindings` routes every slot through `zero_unbound_slot`, whose last
  act is `binding.last_error.clear()` — and `hasBusyBindingsWedgeLocked`'s
  `busyErr` term (Go) is a substring match on exactly that field. Its only other
  route in, `repaired`, needs a forwarding-live (`Ready`) binding, of which a
  fail-closed reconcile leaves none. So auto-rebind recovery could not fire for
  the fault it exists for, silently, while the `auto-rebind GAVE UP` log that
  would have said so is itself inside the same predicate.
  - `Coordinator::last_bind_failures` (slot -> reason) holds the causes.
    `stop_inner` CLEARS it — which is what covers the teardowns that never enter
    `reconcile` (`Coordinator::stop`, the disarm branch of
    `reconcile_status_bindings`, the `no_snapshot` path), so a legitimately
    unbound slot never reports the retired generation's bind error. The
    `BindIncomplete` arm repopulates it from the #6245 explicit
    `BindingSetupFailure`s IMMEDIATELY AFTER calling `stop_inner`: that ordering
    IS the fix, and inverting it is one of the mutations the cells kill.
  - The restore is in `refresh_bindings`, not in a one-shot write into
    `bindings`, because `refresh_status` runs the refresh on EVERY control
    response — a cause restored once is erased within one status poll, well
    inside the Go predicate's 5s dwell.
  - It can never mark a HEALTHY slot: the map is consulted only on the branch
    where a slot has NO `live` entry, and a bound slot always has one.
  - Cells: `bind_failure_cause_survives_the_failclosed_teardown_8558` (the
    ordering, plus two further refreshes standing in for the status polls),
    `a_recovered_reconcile_leaves_no_stale_bind_failure_cause_8558` (the
    self-clearing fault) and
    `a_legitimate_teardown_does_not_inherit_the_bind_failure_cause_8558` (a
    deliberate disarm must not inherit the cause). Manager side:
    `pkg/dataplane/userspace/wedge_cause_recovery_8558_test.go`.
  - NOT covered: the TIMEOUT shortfall (`bound: None` — a worker that never
    reported within `WORKER_STARTUP_BARRIER_TIMEOUT_NS`). It carries no
    per-slot cause to attribute, so recovery still does not fire for it.
    Widening the Go predicate to act on a wedge whose cause is unknown is a
    separate decision: the `maxConsecutiveAutoRebinds` derivation assumes the
    rebind is being fired for a teardown race.

- **Explicit binding-setup failures in the startup report (#6245).** #5143
  reported a bind failure ONLY by OMISSION — the failed slot was simply absent
  from `WorkerStartupReport.bound_slots`, so the barrier could prove
  incompleteness (`bound != planned`) but not say WHY (`worker_loop_setup`
  merely logged + mutated `BindingLiveState.last_error`, discarding the causal
  error, the phase, and the fallback path). The report now ALSO carries the
  EXPLICIT cause: `binding_failures: Vec<BindingSetupFailure>` — one
  `{ slot, phase, reason }` per TERMINAL per-slot failure
  (`BindingSetupPhase::Private` for a private-UMEM bind, `SharedFallback` for a
  shared-group bind whose private fallback ALSO failed), sorted by slot — plus
  `recovered_fallbacks: Vec<BindingRecoveredFallback>` recording shared-UMEM
  groups that failed their group bind but FULLY recovered via private fallback
  (a diagnostic DEGRADATION, sorted by group, that does NOT affect readiness —
  all slots still bound). The readiness criterion is UNCHANGED (`bound ==
  planned` set equality); on a shortfall the barrier records the EXPLICIT cause
  on the typed `ReconcileStage::WorkerBindIncomplete` identity — its
  `WorkerBindShortfall` now carries `failures: Vec<BindingSetupFailure>` cloned
  from the worker's report. Per #6244 the legacy operator string is produced in
  exactly one place: `ReconcileStage`'s `Display`, which appends the rendered
  cause (`render_binding_setup_failures`, co-located with `Display` in
  `reconcile/stage.rs`) for the partial-bind case, so
  `worker_bind_incomplete:<id>:bound=N:planned=M:failures=[private:slot=1:..]`
  names the slot, phase, and reason instead of only the set-difference counts
  (a shortfall with no recorded failure renders `failures=[no-explicit-failure]`
  rather than a blank; the timeout/no-report case keeps the counts-only
  `worker_bind_incomplete:<id>:timeout:planned=M`). The SUCCESS path is
  behavior-identical: a worker that bound its full planned set reports both vecs
  empty. The `force_worker_bind_incomplete` stub now emits a matching explicit
  failure for the dropped slot, so the report->barrier->stage explicit path is
  verified end-to-end without CAP_NET_ADMIN
  (`worker_bind_incomplete_report_carries_explicit_failure_6245`); the pure
  renderer is unit-tested in `reconcile::stage::tests`.

- **`bring_up_workers` is decomposed into cohesive phase helpers (#6240).**
  The 708-line transaction is now a short SHELL that sequences named phase
  helpers, all kept IN `reconcile/bringup.rs` (no one-file-per-phase). The
  helpers are behavior-preserving VERBATIM moves of the pre-#6240 inline
  blocks — only the shell + the helper boundaries change. In shell order:
  `clamp_ring_entries` (the #2524 ring-depth clamp), `plan_workers` (build the
  per-worker `BindingPlan` lists + `live`/`identities` + sizing + the `Planned`
  stage; TAKES the snapshot, reads the map FDs by RAW descriptor while `fds`
  still owns the `OwnedFd`s), `publish_runtime` (MOVE the `OwnedFd`s onto
  `coord.bpf_maps` + publish the mirror-target/CoS owner/active-shard maps),
  `replay_preserved_sessions` (build the command queues + replay preserved
  synced sessions), `ensure_resolver` (best-effort on-demand resolver,
  ATTEMPTED before launch), `spawn_workers` (the ~323-line per-worker spawn
  loop → a typed `LaunchOutcome`), the #5143 `await_readiness` barrier (renamed
  from `collect_worker_startup_readiness`), then
  `start_post_readiness_neighbor_services` (neighbor monitor + warmer + the
  #1881 local tunnel/WG reconcile). The load-bearing ORDER is preserved
  exactly: FD ownership transfer BEFORE any launch; mirror/CoS publication
  BEFORE replay/launch; sessions/queues BEFORE launch; resolver ATTEMPT BEFORE
  worker launch; ALL launches BEFORE the readiness barrier.
  **The #4952 two-armed rollback DECISION stays in the SHELL, distinct and
  visible — `spawn_workers` NEVER calls `stop_inner`.** `LaunchOutcome::SpawnFailed`
  → the shell returns `Err(Spawn)` WITHOUT `stop_inner` (launched records
  survive — structural via #6242's post-spawn-success insert);
  `LaunchOutcome::AllSpawned` → the shell runs the barrier and, on a shortfall,
  calls `stop_inner(false)` (clears ALL). Unifying the arms or moving
  `stop_inner` into a helper REDs
  `reconcile_partial_spawn_failure_preserves_launched_records_6242`. The
  resolver is BEST-EFFORT: `ensure_resolver` returns the installed handle as an
  `Option` (`None` on a spawn failure) and is NOT threaded into `spawn_workers`
  as a required input — the invariant is attempt-before-launch, NOT
  resolver-must-exist (`ensure_resolver_attempts_before_launch_best_effort_6240`).
  The startup-report SENDER is owned by the shell and passed by reference into
  `spawn_workers`, so it stays alive through the barrier — preserving
  `await_readiness`'s exact channel-disconnect semantics.
