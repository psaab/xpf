# #1881 plan v1 — Claude SMR hostile review (round 1)

Reviewer stance: domain SMR (AF_XDP dataplane, HA, thread lifecycle) +
concurrency design. I attempted to break the plan, not synthesize it.

## Verified claims (checked against source, not taken from the plan)

- Frozen clone: `coordinator/mod.rs:540` `let forwarding =
  self.forwarding.clone();` passed by value into
  `local_tunnel_source_loop` (`tunnel.rs:21` `forwarding:
  ForwardingState`). Confirmed.
- `refresh_runtime_snapshot_inner` reconciles WG
  (mod.rs:1158-1168) and never touches `tunnel_sources`. Confirmed.
- Binding-plan exclusion `server/helpers.rs:655` `if iface.tunnel {
  return false; }` → tunnel-only commits hash same-plan. Confirmed.
- `ha.forwarding` ArcSwap stored on refresh (mod.rs:1156), reconcile
  (`reconcile/snapshot.rs` `coord.ha.forwarding.store`), and
  `refresh_fabric_links` (mod.rs:993). A thread holding this handle
  tracks workers exactly. Confirmed.
- F1 keepalive claim: `pkg/routing/tunnel.go:610-621` — keepalive is
  an ICMP dial to the tunnel peer's inner address; the kernel routes
  it into the gr-X TUN; only the local-origin thread reads that TUN.
  Keepalive state therefore follows the frozen state today. Confirmed.
- F3 inbound half: `tx/dispatch/slow_path.rs:157-198` — LocalDelivery
  for a tunnel ifindex looks up `local_tunnel_deliveries`; a missing
  entry falls through to the #1873 R-C blanket gate → DROP. A
  runtime-added tunnel has no delivery entry → inbound decapped-to-
  local traffic drops. Confirmed.
- Q5 (delivery swap race): `slow_path.rs:184-196` already tolerates
  `TrySendError::Disconnected` (counted, exception recorded). The
  plan's rebuild-after-join + single store is sufficient. AGREE.
- TUN open happens inside the spawned thread (`tunnel.rs:36`
  `open_tun` is the first statement of the loop fn) — no blocking IO
  on the control-socket thread. Matches #1866 §7 discipline.
- Test feasibility without privileges: `coordinator/tests.rs:2130+`
  (`wg1866_*`) proves the entry/tombstone lifecycle is testable when
  spawn bodies fail (here: `open_tun` fails without /dev/net/tun →
  thread exits → tombstone). Confirmed.

## Findings

### SMR-1 (MAJOR) — spawn pass reachable with NO live workers (deferred window)

`refresh_runtime_snapshot` runs on the same-plan leg whenever the
helper is armed — including when `defer_workers` was true on BOTH the
previous and current snapshot (`same_plan_apply_needs_binding_reconcile`
only fires on a defer transition). In that window
`self.workers.{handles,live,identities}` are EMPTY. The plan's pass 3
would spawn a GRE thread that freezes EMPTY `live`/`identities`/
`worker_commands` captures for its lifetime: every TUN packet then
fails `select_live_binding_for_ifindex` → per-packet
`no_live_binding_for_tx_ifindex` exception churn, and
`maybe_enqueue_local_tunnel_session` installs shared-map sessions
with zero worker replication. Today's bring-up-only spawn cannot
reach this state. The deferred bring-up does heal it (stop_inner +
respawn), but the plan must pin the rule: **the spawn pass runs only
when worker handles exist** (the WG pass deliberately has no such
gate because WG threads have no binding dependency — the asymmetry
must be explicit, not accidental).

### SMR-2 (MAJOR) — delivery channel lifecycle is underspecified in the entry struct

Plan D.2 stores `delivery_tx` as a stable field of
`LocalTunnelSourceEntry`. Wrong as written:

- the `Receiver` moves into the spawned closure; after a thread
  exits (tombstone) the sender is permanently Disconnected — a
  respawn MUST create a fresh channel pair, so `delivery_tx` is
  per-spawn-attempt state, replaced on every successful spawn;
- a FAILED `spawn_supervised_aux` drops the closure (and the
  receiver) — its sender must never be published;
- publication rule must be: rebuild the map from entries with a live
  handle ONLY (`handle.is_some()`), after pass 2 joins and pass 3
  spawns, exactly once per reconcile.

Required revision: specify channel-per-spawn-attempt + live-only
publication explicitly.

### SMR-3 (MEDIUM) — periodic liveness must republish the delivery map

A thread that dies between applies (F6) leaves its sender in the
published map until the next snapshot apply. Workers tolerate
Disconnected, but the tombstone-only periodic sweep (D.3 last bullet)
tombstones the entry — it must ALSO republish the delivery map after
sweeping (and after its ≤1 respawn), or the map and the entry set
drift until the next commit. Cheap; pin it.

### SMR-4 (MEDIUM) — test plan item 1 mixes a regression baseline into the new suite

"the pre-rotation clone (today's behavior, kept as the regression
baseline assertion) produces the old one" — do not enshrine the bug
as a permanent assertion. The deterministic repro contract is: the
staleness pin is written so it FAILS on current master (frozen clone)
and PASSES with the fix. Phrase it that way; the committed test
asserts only the fixed behavior plus the reconcile-membership pins.

### SMR-5 (MINOR) — per-iteration load vs "per batch" hot-path rule

The project hot-path rule says ArcSwap load per BATCH, not per
packet. Here one iteration ≤ one packet, so per-iteration IS
per-packet — justify explicitly: this loop is syscall-paced (one
`read(2)` per iteration, 1ms sleep when idle, single-digit pps
workload), so one `ArcSwap::load` + `ptr_eq` (~ns) is noise relative
to the syscall; the AF_XDP worker hot path is untouched. The plan
says this but should carry the justification into the code comment.

### SMR-6 (MINOR) — Q2 (attachment identity): accept the fatal-read recovery

`pkg/routing/tunnel.go:132-166` reuse-vs-replace: a replace path
deletes and re-adds the link → new ifindex in the next snapshot →
`attachment_changed` prune. Same name + same ifindex with a dead old
fd requires the kernel to recycle an ifindex instantly, after which
the old fd's reads fail fatally (`local_tunnel_io_error_is_fatal`,
tunnel.rs:7-17) → finished sweep → backoff respawn. The bounded
window (≤ backoff + next liveness tick) is acceptable; an
fd-generation check is over-engineering. RESOLVED as plan-acceptable,
but the plan should state the recovery chain for Q2 instead of
leaving it open.

## Answers to the plan's open questions

- Q1: per-iteration load placement is correct (deferring to idle
  leaves a saturated stream stale). AGREE with plan.
- Q2: see SMR-6 — fatal-read + sweep + backoff is the recovery; close it.
- Q3: disarmed stop-all is correct for symmetry and is a no-op in
  practice (threads are already gone via `reconcile_status_bindings →
  stop()`); keep it, cheap and race-proof.
- Q4: keep the defer-prune. Justification beyond F4: the Go side
  deletes the tunnel netdev at commit; holding a reader fd on a
  deleted-TUN race relies on errno behavior, while the prune is
  deterministic. It is ~15 lines reusing the WG helper shape.
- Q5: existing Disconnected tolerance suffices (verified above).
- Q6: AGREE — no self-exit; single-owner lifecycle in the coordinator.
- Q7: with #1873's owner check + R-C gate I could not construct a
  security-relevant mis-encapsulation from frozen state: a stale
  resolution still carries the OLD egress+endpoint coherently (it
  encapsulates correctly for the old config — wrong-but-well-formed),
  and removed/remapped ids are refused at encap. Severity is
  operational correctness (restart-required staleness, runtime
  add/remove broken), which is exactly what the issue claims. The
  churn bar is cleared: F1-F4 are routine operator actions.

## Verdict

**PLAN-NEEDS-REVISION** — the architecture (Path D) is right and
composes with #1866/#1873/#1188 as claimed; required revisions:

1. (SMR-1) Gate the GRE spawn pass on live worker handles; document
   the WG-vs-GRE asymmetry.
2. (SMR-2) Specify delivery-channel-per-spawn-attempt + live-only
   delivery-map publication.
3. (SMR-3) Periodic liveness sweep republishes the delivery map.
4. (SMR-4) Rephrase test 1: staleness pin fails on master, passes
   with fix; no permanent baseline assertion of the bug.
5. (SMR-6) Close Q2 with the fatal-read recovery chain.
