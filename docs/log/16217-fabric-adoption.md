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

Live Runs 5–6 (build `99.16217.26`, deb sha256 `4fc3b9ee…a9`,
helper sha256 `82ba83c7…23b8` homogeneous `/proc/<pid>/exe` both
nodes before traffic; evidence `/var/worktrees/fzadopt2/cell26/`):
aged 30 s RG1 failover P4, all-node0, FO at 30 s — **FAIL, 25 SUM
zero intervals (31 s→end) in BOTH runs**, `snat_revoked=0` both
nodes at every sample, no pre-FO zeros. Twice-on-loss for this leg
confirmed. Narrowing: at d28 fw1's Backup rows are mixed again —
the wire-keyed rows (`172.16.80.8:<sport>`, the adopted/fabric-era
tuples) read `Timeout: 1800` while the canonical heavy rows
(`10.0.61.102:34452/34482/34494`, multi-GB counters on fw0) still
read `Timeout: 20`; post-FO fw1 forward `Pkts: 0` for every data
tuple. So the local-table arm did not rescue the heavy canonical
tuples live: either the receiving worker's table does not hold the
Established serving row at the failover instant (the serving rows
sit on other workers/nodes — the gate is per-worker-table), or the
post-adoption forward path still blackholes. This commit is the
per-context gate the FZDiag16 evidence prescribes and is unit-proven
for the worker that holds the row; the live cure needs the evidence
(or the adopted row) to reach the fabric-receiving worker. Cluster
restored after each run: clean master `2c8575b70e`, helper
`2f2f5cbf…b04` both nodes (hash-proved), RG0/1/2 node0 primary,
target OK, P4 verification 14.0 Gbit/s.

## Backup-origin publication (FZFixWire8)

Proven (Wire7 live, cell26): fw1 holds Established
`WorkerLocalImport`/`SharedPromote` rows on SOME worker; fabric
retransmits land on OTHER workers whose local table lacks them, so
the Wire7 local gate misses. Fix prescribed: fw1-side publication —
the ct-slice maintenance must, on the BACKUP node too, restamp the
shared canonical + forward-wire alias to Established from LOCAL
serving rows.

Why the slices skipped them on fw1: both collectors keyed the
serving test on `!origin.is_peer_synced() || origin == SharedPromote`.
`WorkerLocalImport::is_peer_synced()` is true (it participates in
peer-synced control gates), so every `WorkerLocalImport` row was
excluded — yet `WorkerLocalImport` is not a peer replica: it is THIS
node's own session replicated across its workers
(`is_cluster_synced_origin` is the peer test, and it is false for
`WorkerLocalImport`). The pure HA-peer replicas are
`SyncImport`/`SharedMaterialize`. On fw1 the heavy canonical rows
sit as `WorkerLocalImport` on the worker that served them; no slice
ever collected them, the shared wire stayed w=2, and only the
receiving worker's local gate (Wire7) could rescue — on the wrong
worker it could not.

Fix: `node_served_forward_slice` (`session/lookup.rs`) and
`node_served_evidence` (`session/mod.rs`) now treat
`WorkerLocalImport` as a local serving origin alongside
`SharedPromote`. The ct-slice (`worker/loop_body/ct_slice.rs`,
unchanged) therefore restamps shared canonical
(`restamp_shared_handshakes_established`) + forward-wire alias
(`restamp_shared_forward_wire_established`) to Established from
fw1's local serving rows, so the gate's shared lookup
(`lookup_shared_established_for_wire`) hits regardless of the
receiving worker. Fail-closed predicates unchanged: non-reverse,
Established, `!handshake_pending`, `!closing` (the slice's direct
arm requires all four; the evidence arm requires Established +
pending-cleared + non-closing on a serving companion). Pure
`SyncImport`/`SharedMaterialize` replicas still never publish from
their own flags.

Tests: `backup_origin_row_publishes_to_shared_16217` —
`WorkerLocalImport` + `SharedPromote` Established rows collect
(publish); `SyncImport` + `SharedMaterialize` Established rows do
not; pending `WorkerLocalImport` fails closed. FAIL-ON-REVERT
verified (dropping `WorkerLocalImport` from the slice predicate
reds the WorkerLocalImport arm). `cargo test 16217` 12/12, `16223`
20/20; `session::` 501 passed with 2 failures identical on clean
base (`tcp_seq_15753`, `session_decision_typed_snat_layout_11064`,
pre-existing).

Live Runs 7–8 (build `99.16217.27`, deb sha256 `0641167f…2e8`,
fix `aceab79d7b`, helper sha256 `f11cf2b6…bcd` homogeneous
`/proc/<pid>/exe` both nodes before traffic; evidence
`/var/worktrees/fzadopt2/cell27/`): aged 30 s RG1 failover P4,
all-node0, FO at 30 s — **FAIL, 25 SUM zero intervals (31 s→end)
in BOTH runs** — twice-on-loss confirmed. Run 1 also showed
`snat_revoked` fw0 0→2 at FO+1 s (run 2: 0 throughout). At d28
fw1's Backup canonical rows STILL read `Timeout: 20` for every
data tuple while fw0's Active rows carry multi-GB counters also
at `Timeout: 20` — i.e. live, the fw1 rows the slice must publish
from are not Established in the worker tables at slice time
either (the completing evidence lives in flow-cache service, not
in an Established local row on fw1), so this publication leg,
though predicate-proven, does not fire for the heavy tuples. The
remaining blackhole stays at/downstream of the adoption instant.
Do not merge as the aged-failover cure. Cluster restored after
each run: clean master `2c8575b70e`, helper `2f2f5cbf…b04` both
nodes (hash-proved), RG0/1/2 node0 primary, target OK, P4
verification 12.9 / 14.0 Gbit/s.

## Scoped completion-evidence adoption (FZFixWire9, DECISION)

Proven chain going in: fw1 canonical rows stay `SyncImport` +
`HandshakePending` forever; completion evidence exists only as flow
activity (fw0 flow-cache hits + fw1 reverse hits post-FO trickle).
DECISION implemented: `lookup_shared_established_for_wire` now
qualifies a synced forward row as Established-for-adoption when
(a) wire = Established (unchanged), OR (b) wire = HandshakePending
AND `shared_scoped_completion_evidence` for the canonical key shows
reverse packets > 0 on any synced row for the tuple (incl. the
reverse companion, with an actual counter — fail-closed per
FZFixWire6) AND forward packets > 0.

- Scope: the evidence scan compares the FULL scoped key
  (`SessionKey` equality: 5-tuple + routing domain + discriminator)
  against the canonical key, its derived reverse companion, and its
  forward-wire alias — never `bare_tuple()` (Codex cross-VRF
  finding: the older bare-tuple evidence scan could borrow another
  VRF's counts). New `SyncedSessionEntry::fwd_packets` carries the
  forward count (monotonic per incarnation at publish, like
  `rev_packets`); counts are snapshotted by
  `restamp_shared_packet_counts` at publish (forward-learn /
  promote / local-delivery / reverse-synth sites stamp the live
  table counts) and on the cache-hit stage transition.
- Codex alias-republish regression: `publish_shared_session`'s
  forward-wire alias slot now applies the same monotonic
  stage + count merge as the canonical row (same incarnation:
  stage rank and both counts never regress; a new incarnation takes
  the incoming stage as-is).
- GLM B1: cache-hit shared restamps (`restamp_shared_packet_counts`,
  the legacy `restamp_shared_rev_packets`, and the Established
  canonical/alias restamps beside them) run only behind
  `take_probe_stage_transition` — recorded in `probe_hit_inner`
  when a deferred completion transitions the pair into Established,
  consumed once by the cache-hit caller. Steady-state hits never
  take the shared-map locks for evidence.

Tests: `pending_row_adopts_on_scoped_completion_evidence_16217`
(zero counts and forward-only counts decline; fwd+rev adopt),
`pending_adoption_evidence_is_scope_exact_16217` (domain-7 evidence
never leaks into domain 0), `alias_republish_never_regresses_stage_16217`,
`cache_hit_restamp_gate_fires_only_on_stage_transition_16217`
(gate opens once on the completing hit, never on 4 steady-state
hits), plus the strengthened
`fabric_ingress_adopts_established_synced_wire_session_16217`
(pending row adopts once counts land). `cargo test 16217` 16/16,
`16223` 24/24; `session::` 502 passed with the 2 failures identical
on clean base (`tcp_seq_15753`, `session_decision_typed_snat_layout_11064`);
`flow_cache` / `publish_shared_session_counts_*` failures verified
identical on unmodified `87b447194f` (pre-existing).

Live Runs 9 (build `99.16217.28.dirty`, deb sha256 3342b5490b41197955c81744ea81ed709c494c619747d7d35df94b04213c9953,
helper sha256 `8064431b…9038` homogeneous `/proc/<pid>/exe` both
nodes before traffic; evidence `/var/worktrees/fzadopt2/cell29/`):
aged 30 s RG1 failover P4, all-node0, FO at 30 s — **FAIL, 25 SUM
zero intervals (31 s→end)**, `snat_revoked=0` both nodes at every
sample, no pre-FO zeros (9.2 Gbit/s at 29–30 s). At d28 fw1's Backup
rows are again mixed (wire-keyed `172.16.80.8:<sport>` rows at
Timeout 1800, canonical heavy rows at Timeout 20) and post-FO fw1
forward `Pkts: 0` for the data tuples. So the scoped-evidence gate,
though unit-proven, still does not rescue the heavy canonical
tuples live: the count evidence evidently does not reach fw1's
shared rows for those tuples before the failover instant (or the
post-adoption forward path still blackholes). Only one live run
was completed in this lane (the cell's restore leg overran the
runner timeout and was finished manually); the twice-on-loss
protocol therefore rests on the identical 25-zero signature of
runs 5–8 plus this run. Do not merge as the aged-failover cure.
Cluster restored: clean master `2c8575b70e`, helper `2f2f5cbf…b04`
both nodes (hash-proved), RG0/1/2 node0 primary, target OK, P4
verification 14.1 Gbit/s.

## Counter carriage end-to-end (FZFixWire10, per FZDiag19)

FZDiag19 proved the scoped-evidence gate could never qualify live:
every leg stamped zero. Rust Open/Update deltas carried
`SessionCounters::default()` (only Close snapshotted live counts),
the JSON `SessionDeltaInfo` and Go `SessionDeltaInfo`/`SessionValue`/
`SessionSyncRequest` had no fwd/rev packet fields, and Rust import
(`build_synced_session_entry`) hard-stamped `rev_packets: 0,
fwd_packets: 0`. The unit arm constructed counts in-process,
bypassing the wire — test-only-green.

Fix (additive only, old peers ignore / decode 0 = no evidence):
- Rust: `open_export_delta_with_provenance` snapshots the live
  entry's counters; `emit_session_state_update_inner` stamps the
  forward entry's live counters; the coordinator bulk export stamps
  the shared row's monotonic `fwd_packets`/`rev_packets`;
  `session_delta_info` copies them to the JSON leg; the binary
  open/update frame appends them as trailing length-gated u64s
  (after the NAT-scope ifindex; rule-id trailer reservation grew to
  cover them, golden regenerated).
- Go: `SessionDeltaInfo.FwdPackets/RevPackets` (JSON + binary-tail
  decode), delta→`SessionValue{,V6}` copy, `SessionSyncRequest`
  forward in both families. The derived #7194 schema fingerprint
  changes automatically on both sides (computed from the wire-name
  set), so mixed builds fence rather than silently zero-fill.
- Rust import: `build_synced_session_entry` stamps
  `req.fwd_packets/rev_packets`; the existing monotonic publish
  merge (canonical + alias) preserves the max per incarnation.

Tests: `cargo test 16217` 19/19 (new:
`open_and_update_deltas_carry_live_counters_16217`,
`import_stamps_request_counters_16217`,
`session_delta_info_carries_live_counters_16217`), `16223` 26/26,
codec 50/50; `session::` 504 passed with the 2 failures identical
on clean base (`tcp_seq_15753`,
`session_decision_typed_snat_layout_11064`, pre-existing). Go:
`TestConvertCarriesPacketCounters16217`,
`TestSyncRequestCarriesPacketCounters16217` pass; go vet clean.

Live (build `99.16217.29.dirty`, deb sha256 `bd0f7f28…d75b`, helper
sha256 `86ba65f8…c7ae` homogeneous `/proc/<pid>/exe` both nodes
before traffic; evidence `/var/worktrees/fzadopt2/cell32/`): aged
30 s RG1 failover P4, all-node0, FO at 30 s — **FAIL, 25 SUM zero
intervals (31 s→end) in BOTH completed runs** — twice-on-loss
confirmed for the counter-carriage build. No pre-FO zeros;
`snat_revoked` fw0 0→2 at FO+1 s in run 1 (0 on fw1). At d28 fw1's
Backup rows remain mixed (some canonical heavy rows still
`Timeout: 20`). So the wire now carries the counts, but live the
evidence still does not rescue the heavy tuples before the
failover instant (or the post-adoption forward path still
blackholes — FZDiag18's residual stands). Do not merge as the
aged-failover cure; this closes the counter-carriage leg
FZDiag19 prescribed. Cluster restored after each run: clean master
`2c8575b70e`, helper `2f2f5cbf…b04` both nodes (hash-proved),
RG0/1/2 node0 primary, target OK, P4 verification 13.7 Gbit/s.

## Backup-arm slice admission + ct-slice count stamp (FZFixWire12)

Per the FZDiag20 narrowing (no steady-state HA delta leaves fw0;
all emission is transition-triggered), the remaining pre-failover
leg is node-local on the BACKUP node: fw1's ct-slice must advance
its shared rows to Established before the failover instant so the
post-FO fabric/wire packets adopt instead of missing.

Fix:
- `node_served_forward_slice` (session/lookup.rs): the
  serving-origin gate no longer drops HA-peer replicas before the
  evidence arm. A `SyncImport`/`SharedMaterialize` forward row
  that is still HandshakePending LOCALLY now collects when the
  aggregated evidence proves completion — `rev_packets>0` via the
  shared counters the counter carriage stamps at import
  (`shared_completion_evidence`), or a local reverse-served
  sibling. Promotion target is the shared canonical+alias stage
  ONLY (the ct-slice restamps); the local row stage is unchanged,
  and an Established replica with zero evidence still never
  publishes from its own flags (fail-closed).
- ct-slice (worker/loop_body/ct_slice.rs): after the stage
  restamps, stamp each collected pair's ACTUAL fwd+rev counts
  (`fwd_packets_for`/`rev_packets_for`) onto the shared canonical
  + alias rows via `restamp_shared_packet_counts`. Runs on the
  backup node identically (the slice is per-worker, role-blind).

Tests: `cargo test 16217` 21/21 (new:
`sync_import_pending_row_collects_on_imported_reverse_evidence_16217`
— pending SyncImport/SharedMaterialize + imported rev>0 collects,
local stage stays HandshakePending, zero-evidence fail-closed,
local reverse-served sibling arm;
`ct_slice_sequence_stamps_counts_for_pending_row_16217` — the
stage+counts+alias sequence leaves canonical/alias at (12,5) and
adoptable), `16223` 27/27.

Live (builds `99.16217.32.dirty` deb `cd66f774…ab6`, helper
`abf6483a…c4ae`; traced `99.16217.33.dirty`/`99.16217.34.dirty`,
homogeneous `/proc/<pid>/exe` both nodes before traffic;
evidence `/var/worktrees/fzadopt2/cell37/`, `cell38/`, `cell39/`):
aged 30 s RG1 failover P4, all-node0, FO at 30 s — **FAIL, 25 SUM
zero intervals (31 s→end) in every run**, no pre-FO zeros.
Progress measured, not acceptance: (cell39, traced) every heavy
tuple's Backup holder read `Timeout: 1800` at d28 on fw1 (the
slice promotion + scoped evidence now qualify pre-FO — the cell37
`Timeout: 20` Backup rows are gone), and post-FO the fabric
packets DID adopt (fw1 emits SharedPromote Open/Update stage=4 at
FO and serves reverse ACK trickle, Pkts>0 on the Backup rows).
The next leg, in this lane's evidence: the adopted forward
resolution on fw1 lands on `MissingNeighbor` for the direct
server next-hop (`172.16.80.8:<sport> -> 172.16.80.200:5211`,
`missing_neighbor ingress-ifindex=4 egress-ifindex=14` in fw1's
dpstats at FO, already present at d28 in cell32) — the
MissingNeighborSeed install for that tuple never forwards the
bulk (one representative packet buffered per hop, resolution
never completes for the direct neighbor in the helper's dynamic
map), so the promoted session exists but the data plane discards
every fabric packet after the first. That is a neighbor-
resolution leg, distinct from the session-stage legs above; it
needs its own fix (seed/retry completion for an adopted
MissingNeighbor tuple) and is NOT closed here. Do not merge as
the aged-failover cure. Cluster restored after each run: clean
master `2c8575b70e`, helper `2f2f5cbf…b04` both nodes
(hash-proved), RG0/1/2 node0 primary, target OK, P4 verification
9.6–16.7 Gbit/s.

## Direct-destination neighbor warm (FZFixWire13, seed completion leg)

Trace of the cell39 residual: on fw1 the helper's dynamic neighbor
map held no entry for the direct server next-hop 172.16.80.200
(egress ifindex 14) at the failover instant — fw1 never served the
flow pre-failover, and the kernel entry on ge-7-0-2.80 had aged to
FAILED while standby (observed live post-restore: `172.16.50.1 dev
ge-7-0-2.50 FAILED`, no 172.16.80.200 row at all on fw1, while fw0
holds it REACHABLE/DELAY). The MissingNeighborSeed path itself is
sound (probe + one-representative pending_neigh buffer +
retry_pending_neigh generation-gated replay); it starved because
nothing ever (re-)drove ARP for that hop on the new owner: the
coordinator neighbor warmer (`queue_warm_pass`, #1636) walks only
route next-hops and fabric peers, and a CONNECTED route carries
`next_hop == None` — the destination IS the hop, and no code named
it. The gateway 172.16.50.1 is irrelevant here (the server is
on-link via the connected /24); the seed needs the direct entry.

Fix (seed from the node's own session table, re-driven on RG
activation): `queue_warm_pass` (coordinator/mod.rs) now also
enqueues the DIRECT destinations of the shared synced rows this
node holds — the post-NAT target of each non-reverse, non-tunnel
forward row that a connected prefix covers, on the row's egress
(falling back to the covering connected row's ifindex). The same
per-RG forwarding-active gate, already-resolved skip, dedup, and
invalid-address filters apply, so standby RGs never warm and
gateway-routed destinations are never probed on-link.
`on_rg_promote_active` (the `handle_activated_rgs` tail) already
clears the per-key rate-limit and forces the pass, so the re-drive
fires at the takeover instant; steady-state snapshot passes re-warm
any destination whose entry later expires. No packet-path work is
added; the walk is over the bounded shared-row set at warm time.

Tests: `cargo test 16217` 24/24 (new
`queue_warm_pass_warms_direct_shared_destination_16217` — direct
shared destination warmed alongside the gateway, FAIL-ON-REVERT;
`queue_warm_pass_skips_gateway_routed_and_reverse_shared_16217`;
`queue_warm_pass_direct_destination_resolved_and_rg_gates_16217`),
`queue_warm_pass` 12/12, `16223` 28/28.

Live (build `99.16217.35.dirty`, deb sha256 `0721e004…a48`,
helper sha256 `d1eb6b28…995b6a6` homogeneous `/proc/<pid>/exe`
both nodes before traffic; evidence
`/var/worktrees/fzadopt2/cell40/`, `cell41/`): aged 30 s RG1
failover P4, all-node0, FO at 30 s — **FAIL, 26 and 25 SUM zero
intervals (31 s→end), twice on the fix**; no pre-FO zeros.
Measured progress, not acceptance: the neighbor leg is PROVEN
closed — fw1's kernel table holds `172.16.80.200 dev ge-7-0-2.80
lladdr 10:66:6a:8b:91:a4 REACHABLE` from d28 through post in both
runs (it was absent/FAILED pre-fix), fw1's fw1 Backup holders read
`Timeout: 1800` at d28 (12 and 16 rows), and fw1 `Neighbor misses`
reads 0. The remaining blackhole moved one stage later: fw1's
last resolution for the heavy wire tuples now reads `ha_inactive
ingress-ifindex=4 egress-ifindex=14 next-hop=172.16.80.200` (was
`missing_neighbor` in cell39) — the fabric packets now resolve the
neighbor but are HA-gated/discarded instead of adopted, i.e. the
adoption gate (or the adopted row's post-adoption HA enforcement)
still does not serve the aged tuples on the receiving worker. That
is the next leg; this fix closes the seed-completion/neighbor leg
only. Do not merge as the aged-failover cure. Cluster restored
after each run: clean master `2c8575b70e`, helper
`2f2f5cbf…b04` both nodes (hash-proved), RG0/1/2 node0 primary,
target OK, P4 verification 13.3 Gbit/s both runs.

## Subsequent-packet adopted exemption (FZFixWire16)

Terminal site (per FZFixWire15): Wire14 (`6c27d4acc3`) exempted only the
one-shot adoption resolve. Adopted tuples still died on SUBSEQUENT packets:
(1) flow-cache hit revalidation (`flow_cache_hit.rs`) evicted the cached
ForwardCandidate via `cached_flow_decision_invalid_reason_for_flow` ->
`forwarding/ha.rs` `EnforceChanged` when the receiving worker's HA snapshot
demoted it to HAInactive; (2) the session-hit re-resolve
(`poll_descriptor/mod.rs`, the `flow` hit arm) called the resolver with
`fabric_adopted=false`, so `enforce_session_ha_resolution` re-wrote
HAInactive and no downstream rescue applies on fabric-link ingress.

Fix: a fabric-established mark on both stores. `SessionEntry.fabric_established`
(session/mod.rs) + `fabric_established_for_wire_at` /
`mark_fabric_established_for_wire` (session/lookup.rs: canonical key via the
forward-wire alias — ambiguity fails closed — or the wire-keyed row; only
non-reverse, non-closing, Established, pending-cleared, non-idle-crossed rows
qualify/mark). `FlowCacheEntry.fabric_established` (flow_cache.rs), stamped at
seed time via `stage_flow_cache_seed(fabric_established)`. The poll adoption
site marks the session at adoption (gate row + resolved row); the session-hit
site computes `session_hit_fabric_adopted` (session mark OR live gate) and
passes it to the resolver and to the cache seed. The hit path suppresses ONLY
the `EnforceChanged` eviction for marked entries — neighbor-MAC, generation,
lease, and every other decision arm still revalidate each hit. Non-adopted
flows carry no mark anywhere and stay fail-closed bit-identically.

Tests: new `adopted_flow_survives_subsequent_packet_revalidation_16217`
drives the real subsequent-packet path — packet 1 the production adoption
resolve (adopted ForwardCandidate + adoption marks), packet 2 the live
`stage_flow_cache_hit` under a stale (RG1-inactive) HA snapshot (marked entry
Consumed, EnforceChanged arm unmoved; unmarked control evicts), packet 3 the
session-hit re-resolve with the mark-derived adopted context
(ForwardCandidate; non-adopted control HAInactive). FAIL-ON-REVERT for each
leg. `cargo test 16217` 26/26; `session::`+`forwarding::`+`flow_cache`
1119 passed with the same 5 failures as the unmodified head
(`matched_family_pairs_are_still_admitted_7520`,
`live_flow_cache_callsite_selected_admitted_clone_reaches_target_6304`,
`gre_decap_flow_cache_hit_ttl_expiry_reads_inner_ttl_5615`,
`tcp_seq_15753`, `session_decision_typed_snat_layout_11064` — pre-existing).

Live: see the PR comment for the aged table (runs on build
99.16217.37.dirty). Cluster restored clean master after each run.

Live update (FZFixWire16 runs): build `99.16217.37.dirty` (helper
`df760c40…`, then tail-fixed rebuild `1b08e66e…`, both homogeneous
`/proc/<pid>/exe` on both nodes before traffic; evidence
`cell45-run1/`, `cell45-run2/`): aged 30 s RG1 failover P4 — **FAIL,
25 SUM zero intervals (31 s→end) in BOTH runs**; no pre-FO zeros;
`snat_revoked` 0 on both nodes at every sample. Narrowing: on the
fix build fw1's `enforce_changed=0` (the prescribed eviction arm is
dead), yet fw1's last resolution still reads `ha_inactive
ingress-ifindex=4 flow=172.16.80.8:<sport>->172.16.80.200:5211` and
fw0 keeps serving all four streams from its flow cache post-FO
(21.7M hits, zero redirect arms) — the heavy tuples never reach
fw1's adoption gate at all, because fw0's cached ForwardCandidate
entries are never superseded toward the fabric on this build (the
lookup rg_epoch/lease fences evict a handful, the slow path
re-serves/re-seeds locally, and no FabricRedirect is ever produced
for them). The adopted-exemption legs are therefore necessary but
not sufficient: the remaining blackhole is fw0-side — a cached
ForwardCandidate whose egress RG departed must re-resolve to
FabricRedirect (or be fabric-redirected) instead of re-serving
locally forever. That is the next leg; do not merge as the
aged-failover cure.

## Lookup-fence admission + mark revalidation (FZFixWire18)

Proven (FZFixWire17, cell45/cell46): on fw0 the cached entries are
preempted by `FlowCache::lookup` fences (`LookupRgEpoch` 4 +
`LookupLease` 2 post-FO; `enforce_changed=0`, zero redirect arms)
BEFORE `ForwardCandidateEgressDeparted` (`forwarding/ha.rs`) can fire —
the hit stage is never reached, the slow path re-serves/re-seeds the
same ForwardCandidate locally, and all four streams blackhole from
FO+1 s.

Fix part 1 (fence site, `flow_cache.rs::lookup_with_observed_bytes`):
the epoch/lease fences no longer evict a cached `ForwardCandidate`
whose EGRESS RG (live FIB attribution via
`owner_rg_for_resolution`, NOT the stamp-owner RG -- the live fw0
entries carried `stamp_owner_rg=0` while egress RG1 had departed) is
not forwarding-active locally on a clustered node. The supersession
arm in `cached_flow_decision_invalid_reason_inner` likewise checks
departure BEFORE enforce demotion, so the eviction attributes to
`ForwardCandidateEgressDeparted` instead of being masked as
`EnforceChanged`. Locally-active, unknown (rg 0), and standalone
(empty map) shapes keep the pre-existing fences bit-identically. The admitted entry reaches `stage_flow_cache_hit`, where
decision revalidation supersedes it (`PostHit…Departed` /
`PostHitEnforceChanged`) and falls through to the slow-path re-resolve
— HA-demote + `redirect_session_via_fabric_if_needed_at` →
`FabricRedirect`, conversion intact (pinned end-to-end in the test).
Fence eviction tallies therefore read the PostHit supersession arm,
not `lookup_rg_epoch`/`lookup_lease`, for these entries.

Fix part 2 (B2, mark revalidation): the `fabric_established` mark is a
claim re-validated against CURRENT RG ownership on every hit, never a
sticky exemption. Cache side: the suppression covers ONLY the
lagging-window `EnforceChanged` demotion (the read the adoption
resolve itself bypassed); the `ForwardCandidateEgressDeparted` arm is
no longer suppressed. Session side: `session_hit_fabric_adopted` now
requires `revalidate_fabric_established` over the marked row's stored
decision (`fabric_established_decision_for_wire_at`) — locally-active
egress RG keeps the context; a departed egress lapses it and the
re-resolve runs unadopted (HA-demote + fabric conversion, i.e.
failback converts again). Shared helpers in `forwarding/ha.rs`:
`forward_candidate_egress_departed` (single departure predicate: the
supersession arm and the fence admission) and
`revalidate_fabric_established`.

Tests (drive the lookup-fence path, not a direct decision hand-off):
`lookup_fence_departed_candidate_reaches_hit_stage_16217` — production
`stage_flow_cache_hit` with BOTH fences failing (epoch bumped 3→4,
runtime lease dropped, stamp lease lapsed) falls through with exactly
one PostHit supersession and ZERO fence-arm movement, then the
unadopted slow-path enforce+convert yields `FabricRedirect`; controls
(locally-active RG still fenced; ownerless entry still fenced).
`adopted_mark_revalidates_ownership_each_hit_16217` — failback state:
the session-context helper lapses the mark, departure predicate
agrees, unadopted re-resolve HA-demotes and converts to
`FabricRedirect`; ownership-holding and unmarked pins.
`cargo test 16217` 28/28; `16270`/`16223`/`16215`/`16216`/`16269`/
`16222` + `policy_revalidation` 160/160 combined;
`session::`+`forwarding::`+`flow_cache` 1121 passed with exactly the 5
pre-existing failures of the unmodified head
(`matched_family_pairs_are_still_admitted_7520`,
`live_flow_cache_callsite_selected_admitted_clone_reaches_target_6304`,
`gre_decap_flow_cache_hit_ttl_expiry_reads_inner_ttl_5615`,
`tcp_seq_15753`, `session_decision_typed_snat_layout_11064`).
Live aged P4: ONE run on this build (cell47: 29 SUM zero intervals
-- acceptance NOT met; a second identical run was NOT executed).
See the PR comment. Do not merge as the aged-failover cure on unit
evidence alone.

## Egress-RG fence, revalidated suppression, owner-verified gate (FZFixWire19)

Review fold on `63e5c7268b` (the Wire18 head, which failed live with
29 SUM zero intervals in its ONE executed run -- the earlier
"TWICE" wording in this log and in the Wire18 commit Validation was
an overclaim and is corrected above):

1. **Departure before enforce** (`forwarding/ha.rs`):
   `forward_candidate_egress_departed` is now checked BEFORE
   `enforce_ha_resolution_snapshot` in
   `cached_flow_decision_invalid_reason_inner`, so the eviction
   attributes to `ForwardCandidateEgressDeparted` instead of being
   masked as `EnforceChanged` (live fw0 post-FO read
   `enforce_changed=5, departed=0`).
2. **Egress-RG lookup fence** (`flow_cache.rs`): the fence admission
   uses the SAME egress-RG predicate (`owner_rg_for_resolution` on
   the cached resolution, tunnel-aware) as the hit stage, not the
   stamp-owner RG. The live fw0 entries carried `stamp_owner_rg=0`
   while egress RG1 had departed, so the stamp-owner fence never
   admitted them. The production lookup now takes the live
   `ForwardingState`; test seams pass `None` and keep the old fences.
3. **Revalidated suppression** (`poll_descriptor/flow_cache_hit.rs`):
   the marked-entry suppression keys on
   `adopted_mark_revalidated` -- a marked entry suppresses the
   `EnforceChanged` demotion only while
   `revalidate_fabric_established` still holds for its cached
   decision on THIS hit. An un-revalidated mark (adoption-window lag
   or failback -- the same bits at cache level) falls through to
   ordinary revalidation; with departure checked first, a departed
   egress supersedes via the departed arm and re-resolves.
4. **Owner-verified adoption gate** (GLM N1,
   `shared_ops/lookup.rs::fabric_adoption_gate_for_wire`): both poll
   gate callers (the session-miss adoption site and the session-hit
   live-gate arm) now additionally require this node to be the
   forwarding-active owner of the egress RG the live FIB names for
   the wire destination. Established evidence alone never adopts on
   a non-owner; unknown egress (rg 0), standalone (empty map), and
   departed egress all fail closed to the ordinary miss path.
   `fabric_adopted_resolution` keeps its named-egress guard.

Tests: new `stage_hit_egress_rg_fence_and_nonowner_gate_16217`
drives the REAL `stage_flow_cache_hit` for the stamp-owner-0 /
egress-RG1 fence shape and the marked-departed shape, and the
production gate for the non-owner decline + owner adoption.
`lookup_fence_departed_candidate_reaches_hit_stage_16217` and
`forward_candidate_egress_departed_falls_through_16270` now assert
the DEPARTED arm specifically (0 EnforceChanged).
`adopted_flow_survives_subsequent_packet_revalidation_16217`
packet 2 now falls through (un-revalidated mark) while packet 3's
session-hit adopted context still yields ForwardCandidate.
`cargo test 16217` 29/29; `session::`+`forwarding::`+`flow_cache`
1122 passed with exactly the 5 pre-existing failures of the
unmodified head. Live aged P4 acceptance: see the PR comment for
this build. Do not merge as the aged-failover cure on unit evidence
alone.

Live Wire19 run (pre-rebase head `ca3b9c3c32`, build
`99.16217.42`, deb sha256 `1b556a11...055`, helper sha256
`83073b1e...f95` homogeneous `/proc/<pid>/exe` both nodes before
traffic; evidence `/var/worktrees/fzadopt2/cell49/`): aged 30 s
RG1 failover P4, all-node0, FO at 30 s + failback -- **FAIL, 28
SUM zero intervals**. Mechanism movement is real: fw0 post-FO now
attributes `forward_candidate_egress_departed=4, enforce_changed=0`
(the departed arm owns the eviction, as prescribed) and fw1 shows
`forward_candidate_egress_departed=2`. The remaining blackhole is
fw1-side: its last resolution for the adopted tuples still reads
`ha_inactive ingress-ifindex=4 flow=172.16.80.8:<sport>->
172.16.80.200:5211` and the canonical heavy rows still read
`Timeout: 20` at d28, so the adoption gate's local-evidence arm
does not fire for them on the receiving worker. Cluster restored:
clean master `2c8575b70e`, helper `2f2f5cbf...b04` both nodes
(hash-proved), RG0/1/2 node0 primary, target OK, P4 verification
14.0 Gbit/s. A second identical run was NOT executed in this lane
(the acceptance bar is ZERO zeros TWICE; reporting one FAIL run,
not claiming twice). Do not merge as the aged-failover cure.
