# Claude SMR hostile plan review — #1870 plan v1, round 1

**Reviewer:** Claude (domain SMR: dataplane session tables, HA sync, CPU/concurrency)
**Plan:** `docs/research/1870-local-tunnel-pair/plan.md` v1 @ `db05781dd`
**Stance:** adversarial — independently re-verified every load-bearing claim
against origin/master `9a536f810` before accepting it.

## Findings

### F1 (High, plan defect): the §2.3 "HA bulk export gap" claim is FALSE

Plan v1 §2.3 claims that while all workers are at cap, local-tunnel sessions
are "absent from owner-RG bulk exports even though the shared maps hold
them." Verified refutation: `export_forward_sessions_for_owner_rgs`
(`session_glue/mod.rs:427-457`) **skips every entry with
`origin.is_peer_synced()`** (`:439-441`) — and both local-tunnel pair entries
carry `SessionOrigin::SyncImport` (`tunnel.rs:202`, `shared_ops.rs:668`),
which is peer-synced (`session/entry.rs:78-83`). Local-tunnel sessions are
therefore **never** bulk-exported from worker tables, at cap or below; the
worker-table absence has zero HA-export consequence. Incremental deltas were
already correctly stated as suppressed. The HA-implications paragraph must be
rewritten: the divergence has **no HA-sync consequence at all** on the
verified paths. This also deletes one of the plan's three impact legs.

### F2 (High, plan defect): "unbounded divergence window / sustained per-packet mutex degradation" is overstated — the reactive materialization path is already uncapped

Plan v1 §2.3 inherits the #1861 row-I13 framing ("divergence window is
unbounded while the table stays at cap", per-packet shared-map mutex
fallback). Verified refutation: `resolve_flow_session_decision`'s shared-scope
hit handling calls `materialize_shared_session_hit`
(`session_glue/mod.rs:949` → `:850-876`), which installs the shared entry
into the worker table via the **uncapped** `upsert_synced_with_origin(…,
false)` — the very same sync-family entry point Path A proposes. So at cap,
the first data packet of the flow that traverses a given worker's session
resolution pulls the entry in anyway (origin relabeled `SharedMaterialize`
via `materialized_shared_hit_origin()`, still peer-synced). The divergence
window is ~one packet per worker per flow, not unbounded — except in the
`should_keep_synced_hit_transient` HA-arbitration arm (`:932-945`), where the
hit is deliberately kept shared-only.

Consequences for the plan:

- The strongest honest argument for Path A is no longer "eliminate sustained
  degradation" but **coherence**: the capped proactive prewarm
  (`UpsertLocal`) refuses entries that the uncapped reactive path
  (materialization) installs moments later from the same shared state. The
  cap on the `UpsertLocal` arm achieves nothing except a transient
  inconsistency, a misleading `create_drops` increment at cap (it counts a
  "drop" that self-reverses on the next packet), and a per-flow-per-worker
  extra shared-mutex traversal.
- Severity drops to Low-Medium. §1/§2.3 must be rewritten to say so
  honestly; the issue body's framing (which predates this verification) must
  not be parroted.

### F3 (Medium): with F1+F2, Q1 (close-as-fixed) deserves a real answer, and the answer is still "fix, minimally"

Re-weighed: do-nothing leaves (a) `create_drops` polluted at cap by
self-healing non-drops — an attribution lie inside the #1871 trio the project
just shipped; (b) the capped/uncapped incoherence between the proactive and
reactive installs of the *same* entries; (c) the partial forward-only
interleaving at cap-1. Path A is ~12 lines, provably behavior-identical below
cap (table verified independently — see F5), and makes the proactive path
match the reactive path it races. That is a justified small fix, but the PR
framing must present F2's diminished severity, not the original "unbounded
divergence" story. Close-as-fixed remains defensible if Codex/AGY weigh (a)-(c)
as not worth any churn; SMR votes fix.

### F4 (Medium, resolves plan Q2): `allow_replace_local=true` is correct, with a verified reason the plan should state

`build_local_origin_tunnel_tx_request` errors out unless the tunnel
resolution disposition is `ForwardCandidate` (`tunnel.rs:171-175`), so
`maybe_enqueue_local_tunnel_session` never runs on a node where the tunnel's
RG resolution refuses forwarding (modulo the deliberate
`allow_unseeded_tunnel_local` prewarm window, `shared_ops.rs:693-708`). The
producer is the local coordinator acting on locally-originated packets —
authoritative-local data. The standby-clobber scenario in Q2 cannot arise
through this producer. Also note: the `allow_replace_local` guard only
protects **non-peer-synced** existing entries (`session/mod.rs:855-860`); a
peer-synced same-key entry is replaced under either flag value, so the flag
choice only matters for the local-entry-collision case where replace is the
status-quo behavior (plan test 3). Fold this into §4/§11.

### F5 (verified, no finding): the below-cap equivalence table holds

Independently walked both bodies (`session/mod.rs:748-812` vs `:834-885`):
identical `remove_entry` → `next_epoch` → record construction (`closing`,
timeouts, `wheel_tick`) → slab insert → `key_to_handle` →
`index_forward_nat_key` → `push_to_wheel`. Delta: install-path `push_delta`
gated at `:797` on `!is_reverse && !peer_synced && !transient` — suppressed
for SyncImport; upsert path pushes none. Return: upsert's only `false` exit
is the guard bypassed by `allow_replace_local=true`. No divergence found.

### F6 (Low): strengthen the pins

Test 1 should also assert hot-path reachability, not just occupancy:
`find_forward_wire_match` for the forward entry and a reverse-key lookup for
the synthesized reverse, plus `entry_with_origin(...)` returning
`SyncImport`. Add to test 3 an assertion that `create_drops()` stays 0 across
the replace (guards against someone "restoring" the capped install). The
per-worker-divergence variant in §2.2 needs no separate test — tables are
independent `SessionTable` values; the at-cap and below-cap tests together
cover both worker states.

### F7 (Low): plan Q4 is resolved and should say so

All `max_sessions` consumers outside the table are telemetry-only
(`worker/loop_body/mod.rs:195`, `worker_runtime.rs`, `server/helpers.rs:167-177`,
`coordinator/status.rs:583` — gauges/status export; slab grows dynamically).
No allocation or invariant consumer of `len() <= max_sessions` found.

## Verdict

**PLAN-NEEDS-CHANGES** — Path A's mechanism and equivalence proof survive
hostile verification (F5), but plan v1's impact analysis contains two
materially false/overstated claims (F1, F2) that change the severity story
and the §11 Q1 weighing. Required for v2: rewrite §1/§2.3 per F1+F2, fold F4
into §4/§11 Q2, fold F7 into Q4, adopt F6 test strengthening, and reframe the
recommendation as a coherence + counter-hygiene fix of Low-Medium severity.
