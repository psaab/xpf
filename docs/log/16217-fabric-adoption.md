# PR #16217 — fabric-ingress established-flow adoption (FZDiag12 shape)

## Finding (FZDiag12, PR head `a1af9ab382` + DISC12 instrumentation)

Aged 30 s P4 iperf3 to 172.16.80.200:5211, all-node0 posture, RG1
failover node0->node1 at 30 s age: 27 SUM zero intervals from
failover+1 s to end of run; `snat_revoked=0` on both nodes at every
sample. Per-tuple evidence (`/var/worktrees/fzdiag12/cell/`):

- On fw0 every re-resolved aged packet leaves via the fabric binding:
  stored `SyncImport FabricRedirect` -> looked `ForwardCandidate
  egress=14` -> enforced `HAInactive`/`ClusterTerminalHAInactive` ->
  final `FabricRedirect egress=4 tx=4 next_hop=10.99.13.2`, SNAT
  `172.16.80.8` (port preserved). No post-failover discard on fw0.
- On fw1 the packets arrive SNAT'd (`172.16.80.8:<sport>`) on fabric
  ingress `if=4` and are discarded as session **misses**:
  `DBG SESS_MISS disp=ClusterTerminalHAInactive egress_if=0
  ingress_if=4` (sampled counts 30-122 per tuple). The pre-NAT session
  keys (`10.0.61.102:<sport>`) never match the NAT'd wire tuple.
- Both HAInactive->FabricRedirect converters are gated
  `!fabric_link_ingress` (anti-loop, correct), `should_seed_fabric_punt`
  requires `!fabric_ingress` and default NAT (both fail), and
  `ClusterTerminalHAInactive` is not slow-path eligible, so
  `slow_path_admit` refuses reinjection and the frame is recycled. No
  session is ever installed on fw1; every retransmit repeats
  miss->discard forever.
- fw1 post-run session rows for the four data tuples show forward
  `Pkts: 0` (only 6-19-packet WAN-return trickles in reverse).

## Fix

On the flow-backed session-miss path in `poll_descriptor/mod.rs`,
before the ordinary miss machinery:

- Gate: `fabric_link_ingress && !has_syn(tcp_flags)` — the physical
  fabric ifindex, not merely a zone stamp. A SYN keeps the existing
  punt/seed behavior exactly.
- `lookup_shared_established_for_wire` (new, `shared_ops/lookup.rs`):
  the shared synced entry for the packet's exact NAT'd wire tuple —
  directly under the wire key, or via the forward-wire alias index
  (ambiguity fails closed) — qualifies only when it is a forward
  (non-reverse) entry whose handshake wire is `Established`. Opening /
  HandshakePending rows and non-TCP rows (wire 0) never qualify.
- On a qualifying entry the packet is resolved through the ordinary
  session-hit path
  (`resolve_flow_session_decision_with_conntrack_and_payload`), which
  materializes the worker row from the synced entry and re-resolves
  to the local WAN egress. Only a resulting `ForwardCandidate` is
  adopted; any other outcome falls through to the ordinary miss path
  and the packet is still discarded (fail-closed).
- Terminal-local: adoption never re-redirects (the adopted decision is
  a local ForwardCandidate; the anti-loop gates are untouched).

Without a synced established entry nothing changes: the packet takes
the ordinary miss path and is discarded exactly as before.

## Regression

`fabric_ingress_adopts_established_synced_wire_session_16217`
(`session_glue/tests.rs`): no synced entry -> lookup declines; a
HandshakePending row -> declines; an Established synced row under the
NAT'd wire key (`172.16.80.8:55068`, canonical `10.0.61.102:55068`)
resolves to `ForwardCandidate egress=12` and installs the worker row.

## Wire advancement (FZFixWire3, FINAL)

FZDiag14 on head `a1af9ab382` + the FZFixWire2 uncommitted diff:
the adoption gate never fired (23 SUM zero intervals). Break:
`node_served_forward_slice` (`session/lookup.rs`) required per-table
companion evidence — local `established && rev_packets>0`, or the
shared Established wire that is this slice's own OUTPUT
(chicken-and-egg). Split across workers, no single table ever
assembled both halves, so the shared wire stayed `w=2`, no
Established Update crossed, and fw1's gate read `w=2` at failover.

Fix: assemble evidence NODE-WIDE where the ct-slice already runs:

- `NodeServedEvidence` gains `rev_packets_any` (reverse service
  observed anywhere node-wide) and `served_completed` (node-wide
  completion stamp); `served_and_completed()` is the collector's
  OUTPUT-ONLY test: (a) any worker's local row Established, OR
  (b) `rev_packets>0` observed for the canonical key in the shared
  synced/replica maps (`shared_completion_evidence`,
  `shared_ops/lookup.rs` — deliberately never reads a shared row's
  Established wire), OR (c) the #16223
  `cache_hit_handshake_progress` completion (worker-table local
  half, folded into the collector). The collector signature now
  takes the shared-map evidence closure instead of a
  `shared_established: bool` that laundered the OUTPUT into an
  input. `promoted_and_served` (import/GC consumers, which may
  trust the wire) is unchanged.
- `emit_session_state_update` emits an HA Update for peer-synced
  rows when the handshake stage alone advances to Established
  (close-class transitions stay silent), so the delta crosses to
  the peer. `lookup_shared_established_for_wire` (the gate) is
  unchanged; import remains a faithful conduit.

Tests: `split_two_workers_neither_alone_sufficient_16217` — worker
A Established with zero local reverse counters (strict slice
insufficient), worker B a pending replica, collector table C
pending: A-alone and C-alone collect nothing, the aggregated
evidence (b) and (c) each collect the tuple, zero evidence collects
nothing. Plus
`split_serving_established_replica_pending_completes_and_announces_16217`,
`peer_synced_close_transition_stays_silent_16217`,
`forward_wire_alias_restamp_advances_wire_key_16217`. All DISC14
probes stripped (zero `DISC14` hits in the tree).

## Live acceptance

Run 1 (build `99.16217.23.dirty`, deb sha256 `544065a3…08b`,
helper `/proc/<pid>/exe` sha256 `471b6338…229` homogeneous both
nodes before traffic; evidence `/var/worktrees/fzadopt2/cell23/`):
aged 30 s RG1 failover P4, all-node0, FO at 30 s — **FAIL, 25 SUM
zero intervals** (31 s→end), `snat_revoked=0` both nodes. Pre-FO
throughput 6.6–7.2 Gbit/s with no zeros; the failover leg is still
broken. Session dumps narrow it: at d28 fw1's Backup rows for the
two heaviest streams (37910/37926) still show `Timeout: 20`
(HandshakePending, `w=2`) while lighter streams already read 1800 —
the wire for the heavy split streams never advanced pre-FO despite
this fix, so fw1's adoption gate still read `w=2` at the failover
instant (same signature as FZDiag14, now stream-selective). The
remaining gap is upstream of the collector predicate: the evidence
assembly must run on the cadence that actually reaches the heavy
streams' workers/tables within the handshake window (the ct-slice
is gated on the 10 s conntrack-refresh cycle). Cluster restored:
clean master `2c8575b70e`, helper `2f2f5cbf…b04` both nodes,
RG0/1/2 node0 primary, target OK, P4 verification 14.1 Gbit/s.

## Wire-cadence residual (FZFixWire4)

Residual after Run 1: node-wide evidence works but ct-slice assembly
is gated on the 10 s `CT_REFRESH_WINDOW_NS` cycle — heavy split
streams' wire stayed `w=2` pre-failover.

Fix: at the moment `cache_hit_handshake_progress` detects completion
for a tuple (the flow-cache hit path in `stage_flow_cache_hit`, right
after `emit_probe_hit_state_update` publishes the HA stage-advance
Update via the emit carve-out), immediately advance the shared
canonical slot (`restamp_shared_handshake_established`, already
present) AND the forward-wire alias slot
(`restamp_shared_forward_wire_established`) to Established — same
packet path, bounded work, existing shared-map locks only, no
ct-slice wait. The ct-slice remains the backstop for completions
that never take a cache hit. No probes added.

Tests: `split_cache_hit_completion_collects_without_ct_slice_16217`
— split-shape completion via the cache-hit path (`probe_hit` on
promoted pairs) lands Established on both halves, queues the HA
Update, and the collector collects the tuple with zero shared
evidence (no ct-slice run); the replica half completes from node
evidence on its next served hit and emits the stage-advance Update.
`cargo test 16217` 5/5, `16223` 15/15, `session::` 496 passed with
4 failures (`icmp_error_budget_9901` x2 — flaky under parallel load,
pass in isolation; `tcp_seq_15753`,
`session_decision_typed_snat_layout_11064` — pre-existing on base).

Live Run 2 (build `99.16217.24.dirty`, deb sha256 `dc7bb96e…f0`,
helper sha256 `a8d35d77…8d` homogeneous `/proc/<pid>/exe` both
nodes before traffic; evidence `/var/worktrees/fzadopt2/cell24/`):
aged 30 s RG1 failover P4, all-node0, FO at 30 s — **FAIL, 25 SUM
zero intervals** (31 s→end), `snat_revoked=0` both nodes. Pre-FO
9.7–10.7 Gbit/s, no pre-FO zeros. Narrowing vs Run 1: at d28 fw1's
Backup rows for the two heaviest streams (37910/37926) now read
`Timeout: 1800` — the wire advanced pre-FO, so the adoption gate
no longer reads `w=2` for those tuples. The remaining blackhole is
downstream of adoption: post-FO the adopted rows exist (Timeout
1800, both nodes) but forward WAN traffic stays zero — the
post-takeover forward/reply path for fabric-era sessions, the same
residual FZFixHandshake2 named. Cluster restored: clean master
`2c8575b70e`, helper `2f2f5cbf…b04` both nodes, RG0/1/2 node0
primary, target OK, P4 verification 9.6 Gbit/s.

## Export stamp + fail-closed evidence + lock order (FZFixWire6)

Three changes on top of `18266af606`:

1. **Export stamp.** When node-wide completion evidence holds for a
   tuple, exported `tcp_handshake_state` is Established at all three
   export sites: `open_export_delta_with_provenance`
   (`session/install.rs`, table evidence via
   `SessionTable::completion_evidence_for`, plus the
   `open_export_delta_with_shared_evidence` variant that merges the
   shared-map half), `emit_session_state_update`
   (`session/mod.rs`, funneled through
   `emit_session_state_update_inner`; the
   `emit_session_state_update_with_shared_evidence` variant merges
   caller-gathered shared evidence), and the coordinator bulk
   snapshot (`afxdp/ha/export.rs`, evidence computed over both shared
   maps under the canonical lock order). Evidence source is
   `shared_completion_evidence` over the shared maps merged with the
   table's node-served stamps — the shared row's own Established wire
   is never an input (it is this stamp's output).
2. **Fail-closed evidence.** `shared_completion_evidence`
   (`shared_ops/lookup.rs`) now requires an actual reverse PACKET
   COUNT > 0 read off a shared row (`SyncedSessionEntry::rev_packets`,
   snapshotted from the serving forward entry's admitted
   `counters.rev_packets` at publish/promote/local-delivery/learn
   time and refreshed by the ct-slice and cache-hit restamps via
   `restamp_shared_rev_packets`; monotonic per incarnation at the
   publish choke point). Mere existence of a synthesized reverse
   companion (published with `rev_packets = 0`) never counts. The
   pre-fix code set `rev_packets_any = 1` for any reverse row present.
3. **Lock order.** `restamp_shared_forward_wire_established` held
   the forward-wire guard while locking `shared_sessions` inside its
   loop (AB-BA against `shared_completion_evidence`'s
   sessions-then-wire). Unified: always `shared_sessions` then
   `shared_forward_wire_sessions`; the restamp now snapshots the
   canonical rows under `shared_sessions`, drops that guard, then
   takes the wire guard. The bulk snapshot holds both guards in the
   same order for its whole walk.

Tests (all mutation-checked): `export_stamp_open_delta_established_on_node_evidence_16217`,
`export_stamp_update_established_on_node_and_shared_evidence_16217`,
`bulk_export_stamps_established_on_shared_reverse_count_16217`,
`completion_evidence_requires_actual_reverse_count_16217`,
`restamp_and_evidence_share_one_lock_order_16217`. Reverting each
stamp/evidence arm turns its test red (verified for the Open-delta,
Update, and evidence arms; the bulk arm shares the verified
`evidence_for` predicate shape).

Live Run 3 (build `99.16217.25.dirty`, deb sha256 `13115f69…b508`,
helper sha256 `41a057f2…0d92` homogeneous `/proc/<pid>/exe` both
nodes before traffic; evidence `/var/worktrees/fzadopt2/cell25/`):
aged 30 s RG1 failover P4, all-node0, FO at 30 s — **FAIL, 25 SUM
zero intervals** (31 s→end), `snat_revoked=0` both nodes at every
sample. Pre-FO ~6.4 Gbit/s (28–30 s), no pre-FO zeros. Narrowing vs
Run 2: at d28 fw1's Backup rows are mixed — two tuples already read
`Timeout: 1800` while the two heaviest streams still read
`Timeout: 20`, i.e. the export/adoption wire is still not uniformly
Established at the failover instant for exactly the heavy split
streams. The remaining blackhole stays downstream of / at the
adoption instant for those tuples. Cluster restored: clean master
`2c8575b70e`, helper `2f2f5cbf…b04` both nodes (hash-proved),
RG0/1/2 node0 primary, target OK, P4 verification 13.6 Gbit/s.

A second identical run was executed for the twice-on-loss
requirement; its table is recorded with the PR comment.
Live Run 4 (same build `99.16217.25.dirty` / helper `41a057f2…0d92`,
evidence appended to `/var/worktrees/fzadopt2/cell25/cell.log`):
aged 30 s RG1 failover P4 — **FAIL, 25 SUM zero intervals** again,
`snat_revoked=0` both nodes. Twice-on-loss confirmed. Cluster
restored: clean master `2c8575b70e`, helper `2f2f5cbf…b04` both
nodes (hash-proved), RG0/1/2 node0 primary, target OK, P4
verification 11.3 Gbit/s. (The run-4 restore leg initially left fw0
on the fix build after a rolling-upgrade rejoin timeout; fw0 was
then redeployed clean and re-verified homogeneous.)

## Local-table evidence arm (FZDiag16)

FZDiag16 on head `e0f0b9ff80` proved the export stamp never fires for
the heavy split tuples: on fw0 the forward half is a peer-synced
`SyncImport` row stuck in pure Opening (the completing SYN-ACK/ACK is
fabric-served on fw1), and every evidence collector excludes
peer-synced origins, so no Established export ever crosses. At the
failover instant fw1 holds local `WorkerLocalImport`/`SharedPromote`
rows Established (wire=4) for those tuples, but the adoption gate
(`lookup_shared_established_for_wire`) read only the shared maps —
whose fw1 rows are the fw0 imports stuck at w=2.

Fix: the fabric-ingress session-miss gate
(`poll_descriptor/mod.rs`, `fabric_link_ingress && !SYN`) now uses
`fabric_adoption_established_for_wire` (`shared_ops/lookup.rs`):
shared Established qualifies as before; ELSE the worker-local table
is consulted via `SessionTable::local_established_for_wire_at`
(`session/lookup.rs`), which derives the canonical key from the wire
key (forward-wire alias match — ambiguity fails closed — or a direct
probe of the wire key) and qualifies only a non-reverse, non-closing,
non-peer-synced local row that is Established with `handshake_pending`
cleared and not idle-crossed. Pending/closing/reverse-only and
peer-synced local rows never adopt. On a qualifying gate the packet
still re-resolves through the existing
`resolve_flow_session_decision_with_conntrack_and_payload` path and
only a `ForwardCandidate` outcome is adopted (fail-closed otherwise).

Tests: `fabric_gate_adopts_on_local_established_when_shared_pending_16217`
— shared maps w=2 only: local Established (WorkerLocalImport and
SharedPromote) adopts and derives the canonical key; empty table,
local Opening, peer-synced Established, and reverse-only Established
all decline. FAIL-ON-REVERT: dropping the local arm turns the
Established-local assertions false.
