# #1881 plan v2 — Claude SMR hostile review (round 2)

Scope: re-attack plan v2 (commit b355aa743), focusing on the new
mechanisms (D.1b rotation gate, two-store delivery publication,
drain stop check, SMR-1 gate) and the 5 new §11 questions.

## Worked traces

### Q1 — parked thread still WRITES deliveries: RATIFIED HARMLESS

Trace (mode flip / removal / reattach, same id):

1. `refresh_runtime_snapshot_inner` stores the new forwarding Arc.
2. The thread rotates, gate goes false, parks (no builds).
3. Can a worker still enqueue NEW deliveries into the parked
   thread's channel? Delivery requires a worker-resolved
   `LocalDelivery` disposition with `resolution.local_ifindex` equal
   to the channel's map key (`tx/dispatch/slow_path.rs:156-162`).
   - Worker on the NEW Arc: removal/mode-flip ⇒ no GRE resolution
     marks that id ⇒ no delivery at all (mode-flip WG delivery uses
     the WG machinery, and the NEW logical_ifindex of a reattached
     endpoint ≠ the parked thread's map key ⇒ lookup miss ⇒ #1873
     R-C gate drop).
   - Worker still on the OLD Arc (≤1 tick): the delivery is decapped
     under the OLD state and written to the OLD TUN — byte-identical
     to pre-commit behavior, bounded by one worker tick.
4. Therefore everything the parked thread writes is either
   old-state-correct (one tick) or already-queued backlog from
   before the rotation; the kernel locally delivers inner packets
   addressed to the firewall exactly as it did pre-commit. No
   harmful trace found. Draining-while-parked is in fact REQUIRED to
   keep the channel from sitting full across the unpublish window.

### Codex r1 MAJOR 1 closure — mode-flip trace through D.1b

gre→wireguard same id, same name: new state has
`ep.mode == "wireguard"` ⇒ `endpoint_attachment_valid` false on the
very rotation that made the hazard possible ⇒ park before any build
against the new state. The packet that raced the rotation (built
against the OLD Arc) is old-state-coherent and its encap passes the
old owner check — wrong-but-well-formed for the old config, the
accepted RCU semantics everywhere else in this dataplane. CLOSED.

### Codex r1 MAJOR 2 closure — busy-producer join trace

Producer (worker) holds map Arc loaded BEFORE store #1 → can keep
try_send-ing into the stale channel. But the drain loop now observes
`stop` per chunk, so the joining coordinator waits at most one drain
chunk + one read + one bounded build, regardless of producer
behavior. After store #1, fresh per-packet loads
(`slow_path.rs:159-162`) cannot obtain the stale sender; residual
sends hit Disconnected (tolerated, counted). BOUNDED. CLOSED.

## Findings (all wording-level; none structural)

### SMR2-1 (MINOR, required edit) — store #1 rule precision

D.2 pass-2 says store #1 is "rebuilt without the stale entries". The
rule must be the SAME live-handle-only rule as store #2 applied to
(entries − stale set): pass-1 tombstones (finished threads) must
also be excluded from store #1, not just pass-2 stale entries. One
sentence; fold into v3.

### SMR2-2 (MINOR, required edit) — disarmed leg must store the empty delivery map

`stop_all_local_tunnel_sources("disarmed")` must also
`local_tunnel_deliveries.store(Arc::new(BTreeMap::new()))` (as
`stop_inner` does at mod.rs:377-379). v2 implies it; pin it.

### SMR2-3 (NOTE, no edit) — bring-up ordering assumption

D.3 asserts the SMR-1 gate is satisfied at bring-up because workers
exist when `bringup.rs:445` runs. Engineer phase must verify
`coord.workers.handles` is populated before that call (it follows
the worker spawn loop in the same function); if a future refactor
moved it earlier, the gate would silently no-op bring-up spawn. Add
a debug assertion or a test pin (§9 item 2 last bullet covers the
no-worker case; add the inverse: bring-up WITH workers spawns).

## Answers to §11 (round-2 questions)

- Q1: ratified harmless — trace above.
- Q2: two-store is sufficient — per-packet map load + Disconnected
  tolerance; no generation check.
- Q3: `!handles.is_empty()` is the right predicate — `live`/
  `identities` are populated from the same bring-up pass that fills
  `handles`; sparse ids are indistinguishable from today's behavior.
- Q4: two BTreeMap lookups + string compare on Arc rotation only
  (config applies, ~1/s worst case) — no objection.
- Q5: RG-promote does not rotate the forwarding Arc (no gate
  recompute, none needed — RG state is read live via `ha_state`).
  `refresh_fabric_links` DOES rotate it (mod.rs:993): tunnel rows
  are cloned unchanged, so the gate recomputes to the same value —
  benign. No missed interaction found.

## Verdict

**PLAN-READY** — contingent on folding SMR2-1 and SMR2-2 (two
single-sentence edits) into v3 verbatim. The architecture, the
window closures, and the test matrix are sound; no structural
finding survived this pass.
