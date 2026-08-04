# #6751 plan — interface SNAT no-PAT admission: reserve-or-PAT the colliding translated tuple

- **Status**: DRAFT v15.29 — round-40 fold (Codex r40's two
  blockers + major + minor; AGY r40 converged PLAN-READY with zero
  findings: window authority is bound PER WINDOW (recorded at its
  BulkStart from the peer's capability state at that moment), a
  non-capability window's resolution is DISPOSITION-ONLY (the
  quarantine's confirm-vs-admit runs as today but every admitted
  suspect keeps its mark UNRESOLVED — no confirmation, purge,
  clear, or definitive pass — while genuine rows import normally,
  so the legacy table never regresses), and the capability
  advertisement moves OFF the periodic ticker onto an ORDERED
  PRE-DATA send (handshake → capability frame → any bulk/delta
  frame) with UNKNOWN treated as non-capable and a FRESH CAPABLE
  PRIME forced when capability is first learned mid-connection;
  the quiet interval is DERIVED from the peer's actual
  disconnect-detection bound (≈20s read-deadline-plus-two-misses
  for ACK-capable peers, sync.go:90 / sync_conn_read.go:33 — not
  2.5×keepalive), the degraded terminal is FENCE-OWNED and
  DISCONNECTED-ELIGIBLE (the connected-only 5s readiness timer
  and its no-release-without-reconnect regression are preserved
  intact; classic RETH VRRP's 30s hold and the private-RG gate
  are the named outer bounds); and the debt is TWO SEPARATE
  DEBTS — the sender delivery/ACK debt discharges at BulkEnd-ACK
  while the receiver ALIAS-PROOF debt discharges ONLY on a
  capability-advertising definitive snapshot or the suspect row's
  own close, never at a legacy both-empty transition — with the
  retained-C0 regression pinned in §9)
- **Issue**: #6751 (opus-review-001 R08, High, `bug`+`audit`+`security`) —
  interface SNAT admits indistinguishable no-PAT return tuples and sends
  replies to the FIRST session.
- **Base**: `ad9591177481` (origin/master at research start).
- **Scope**: `userspace-dp` Rust dataplane + Go snapshot-builder overlap
  foreclosure + Go commit-validator extension (§5.7) + additive optional
  status counters (§5.8). No breaking wire change, no `NatDecision`/
  `SourceNatLookup` shape change.
- **Core invariant** (round-3/4 reviewers' formulation, adopted): EVERY
  reachable session owns exactly one translated identity, held continuously
  from before it is reachable until after it is not — across admission,
  publication, replication, materialization, tuple-changing re-sync,
  reconcile replay, snapshot rebuilds, drain transitions, HA transitions,
  link stop→rebind cycles, worker teardown, and helper restart. Scoped
  (SMR r5 N16): the queue/relay-or-expiry-bounded reverse-companion edge
  is excluded — identical in shape to shipped pool-mode discipline today;
  see §5.6.

---

## 1. Issue framing

Interface-mode source NAT (`set security nat source rule-set RS rule R then
source-nat interface`) rewrites the source ADDRESS to the egress interface's
own address and PRESERVES the source port (`nat/source.rs:1226-1251`). It
mints no allocation, no reservation, no occupancy token of any kind. Two
internal hosts that pick the same source port to the same server:port over the
same protocol therefore produce ONE external five-tuple:

```
H1 10.0.0.1:5555 -> S:80  --(iface SNAT to E)-->  E:5555 -> S:80
H2 10.0.0.2:5555 -> S:80  --(iface SNAT to E)-->  E:5555 -> S:80   (same tuple)
reverse wire key for both: (S:80 -> E:5555)
```

The #4399/#4438 1:N multimaps keep BOTH forward handles in the reverse-key
bucket, but candidate validation
(`reply_matches_forward_session`, `session/key.rs:19`) recomputes the SAME
translated tuple for both sessions, so both validate and
`find_forward_nat_match` (`session/lookup.rs:222`) returns the first-installed
handle deterministically. `install_reverse_session_from_forward_match`
(`afxdp/session_glue/mod.rs:1294`) then derives the reverse rewrite/delivery
from that handle: every reply for the ambiguous tuple is un-NAT'd to H1 — a
cross-session data leak (H2's return traffic delivered to H1) with
wrong-session reset/state damage projected for both flows (the pinned tests
prove the misdelivery; the packet-level RST lifecycle is inferred, and the §9
smoke test will demonstrate it). On the cross-worker shared maps
(`afxdp/shared_ops.rs:897` `publish_shared_session`) the collision is worse:
`shared_nat_sessions` is single-value, so the second publish DISPLACES the
first (counted by `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS`) and which host wins
depends on RSS worker topology — non-deterministic per-flow hijack. No packet
field can disambiguate after admission: the reply `(S:80 -> E:5555)` carries
zero identifying header fields, and no index (SessionKey/NatDecision/metadata)
holds inner-host, ingress-ifindex, zone, or VRF context on the reverse path
(#2387, open, is exactly that gap).

The production test suite PINS the misdelivery:
`session/tests.rs:4560` (`nat_reverse_1n_collision_preserves_displaced_return_path`)
constructs exactly this two-host interface-SNAT collision and at
`session/tests.rs:4602-4610` asserts the reply resolves to the FIRST-installed
session because "the wire tuple is genuinely ambiguous under no-PAT interface
SNAT". The codebase encodes the bug as expected behavior.

## 2. Honest scope/value framing

This is a correctness/security fix, not a performance change. The absolute
win:

- Eliminates a silent cross-session data leak (one internal host receives
  another host's return traffic — confidentiality/integrity violation on a
  box whose job is traffic separation), the wrong-session state damage, and
  the non-deterministic shared-map displacement variant.
- Narrows a Junos-parity gap: official Juniper documentation states that
  interface NAT always performs PAT (Codex r2, citing Juniper's Source NAT
  topic map), and the Junos grammar carries `security nat source interface
  port-overloading off` to tune interface-mode port REUSE (in-repo: #4291
  records the knob accepted-and-advisory at
  pkg/config/compiler_nat_source.go:253-271). xpf's port-preserving
  interface mode is the outlier. Preserve-first + PAT-on-collision (§4) is
  an INTENTIONAL xpf semantic — wire-stable for non-colliding flows — not
  claimed literal Junos parity (Junos allocates unconditionally).
- Collision frequency today: requires same protocol + same source port +
  same server + simultaneous liveness. Rare for random-ephemeral TCP, but
  realistic for ICMP echo (Linux ping reuses small per-socket identifiers),
  for UDP services with pinned source ports, and for any middlebox that
  normalizes source ports. It is also a deterministic insider primitive
  (deliberate squatting; UDP/ICMP need no handshake).

If reviewers conclude the fix's churn exceeds the risk, PLAN-KILL is an
acceptable verdict — PLAN-KILL here means shipping option (c), status quo
plus documentation, and saying so on the issue.

## 3. What's already shipped / partially batched

| Prior work | What it gives this plan |
|---|---|
| #4399/#4438 1:N multimaps + validate-on-lookup | Defense-in-depth retention for the OTHER non-bijective classes (DNAT-shared-backend, NAT64, static). |
| **#5269/#5336/#5338/#5341/#6041/#6226** address-only occupancy token (`reserve_address_only`, `address_only_owners`, `release_flow`/`rollback_flow` address_only arm, `reserve_flow` stale-tuple-drop at allocator.rs:1666-1676) | THE mechanism option (a) is built on: identity-keyed occupancy `(protocol, translated_ip, translated_port, dst_ip, dst_port)`, ONE-mutex mint, idempotent re-entry, fail-closed collision. Preserve AND PAT both mint this token shape; release/rollback verbatim (allocator.rs:1318/1392). |
| #5144 strict overlap validator (compiler_validate_strict_nat.go:2525-2576) + `pool_failure`/`PoolUnusable` channel (nat_source.go:118-122; NAT64 native empty-pool fail-closed at nat64.rs:1123) | The two-layer foreclosure pattern §5.7 extends. |
| #4388/#4512 synced reserve + coordinator publish path (ha/session_import.rs) | The HA reservation points §5.6 makes transactional. |
| #4518 NAT64 allocator carry-over across reloads | The drain-domain retention precedent for §5.7. |
| #4074/#4088 ICMP id translation; #1852 + #2562/#5146 + #6122 fragment machinery | The ICMP/fragment stories, unchanged. |
| #4676 `gc_expired_chunked` | The §4.3 probe chunking discipline. |
| SessionManager coordinator-owned shared maps (coordinator/session_manager.rs:12 → worker/launch.rs:130) | The registry placement precedent. |
| #1760 W3' status-counter plumbing (protocol/control.rs:343, coordinator/status.rs:241, server/lifecycle.rs:228, server/helpers/status.rs:102, protocol_status.go:287, pkg/api/metrics.go:377/791, metrics_descriptors_userspace_session.go:27, metrics_userspace.go:677) | The additive-counters precedent §5.8 follows — full inventory (Codex r3 major 7 + r4 minor 9). |
| **OPEN #6522** — sibling replica reap releases a live flow's SNAT allocation | The new registry's holder model (§5.6) is designed so this hazard cannot exist in it; pool-side fix remains #6522's own issue. |

## 4. Multiple Path Options (the design fork)

### 4.0 The round-32/33 substrate fork — ADJUDICATED: PATH A (sole-writer helper)

Rounds 1-29 settled the (a)/(b)/(c) behavior fork. Round 32 asked whether
the mirror substrate could be defended at proportionate cost; v15.20 put
PATH A (fold r32 into the machinery) against PATH B (table-truth
retreat). Round 33 adjudicated it, and the answer rests on CORRECTED
FACTS, not preference:

- **The r32 control-socket foreclose was factually wrong** (owned —
  SMR r33 and AGY r33's PATH-A rejections both rested on it). The
  helper binds TWO Unix listeners: the shared control socket AND a
  DEDICATED session socket (`userspace-dp-sessions.sock`, derived
  from the control path — lifecycle.rs:165-175,
  process_control.go:172-178). HA imports already ride the session
  socket (`SetClusterSyncedSessionV4/V6` → manager_ha.go:1112-1167),
  serviced on a dedicated thread (lifecycle.rs:344-381). Making the
  helper the sole mirror writer changes WHERE the mutation executes,
  not the transport's traffic class — nothing new touches the shared
  control socket's >1/s budget.
- **PATH B as specified in v15.20 had four factual errors** (Codex
  r33, each verified): (i) the helper has NO gRPC server — it serves
  newline-delimited JSON over Unix streams (handlers/mod.rs:44-89);
  (ii) the "authoritative SessionTable" is per-worker PRIVATE
  (setup.rs:28-42) and the coordinator's shared aggregate is
  reconcile-EPHEMERAL — a normal reconcile snapshots, destroys, and
  replays it with retagged provenance (`WorkerLocalImport`,
  session_glue/mod.rs:868-878) that the existing owner export
  EXCLUDES (session_glue/mod.rs:608-635), so the named export can
  omit valid local sessions after any reconcile; (iii) no mutation
  sequence exists to order pages against a Go generation horizon
  (`install_epoch` is per-worker private and resets,
  session/mod.rs:343-349; `session_id` is write-once,
  session/mod.rs:459-470; #2170 generations are Go-assigned at queue
  time, worker/mod.rs:383-389); and (iv) the "helper tables never
  contain aliases" premise was false — imported alias rows install
  into worker tables (upsert_synced.rs:64-78) and after promotion
  export as locally-originated. The mirror also retains
  non-cosmetic consumers (receiver absence reconciliation,
  session_store.go:613-672; policy invalidation; clear-all and
  filtered clears; neighbor warming), so "mirror becomes cosmetic"
  was false. A redesigned table-truth ("B2" — durable table
  ownership across reconcile, a coherent cross-worker cut, page
  cursor semantics, dual-lane dedup, alias provenance, table-native
  receiver reconciliation, policy/clear APIs, sweep-to-debt
  conversion) is a LARGER design than PATH A, and is noted as
  possible future work, not this plan.
- **AGY r33's strongest PATH-A objection — the unbounded per-worker
  `VecDeque` command queues (bringup.rs:426-432) — is a REQUIRED
  FEATURE of PATH A, not a foreclose**: bounded admission with
  explicit refusal is rule 2 of the specification below.
- **No kill shot against the option-(a) registry core exists in
  either substrate** (both reviewers confirmed independently): the
  registry, occupancy split, holders, drain, static accounting,
  #2170 delta discipline, and alias machinery never read the mirror
  for their own correctness.

**PATH A — the helper becomes the SOLE writer of session mirror
rows, with an exact-incarnation transaction discipline — is the
adjudicated substrate.** §4.0.1 specifies it; §4.0.2 maps the
consequences onto the surviving §5.x machinery.

#### 4.0.1 The sole-writer specification (PATH A)

1. **Sole-writer rule with the COMPLETE writer inventory** (Codex
   r33 finding 2's "not a two-call-site change"): every mutation of a
   session mirror row — local publish (publish_conntrack.rs), the
   last_seen/policy_id refresh writers (bpf_map/mod.rs:364/438),
   close deletes (session_delta.rs:420/426/444/445), imported
   forward/reverse installs (manager_ha.go:1112-1167/1265-1303),
   Go-constructed reverse/DNAT companions (session_store.go:274-350),
   policy invalidation (daemon_policy_invalidate.go:357-386 →
   manager_ha.go:1392-1412), filtered clears (cli_clear.go:336-550,
   server_sessions.go:1293-1543), clear-all
   (maps_session.go:405-528), AND the #5305 pre-image rollback
   (`restoreBPFSessionV4Locked`/`V6Locked`, manager_ha.go:1204-1331 —
   direct Go `SetSession`/`DeleteSession` pre-image restores on a
   failed sync install, AGY r34 minor 3; the rollback becomes a
   helper-transactional restore over the session socket), the
   initial-control cleanup (maps_sync.go:577/642 — direct
   `ctMap.Delete` with no incarnation check and no Close; it becomes
   a helper-transactional cleanup with exact per-row results, and
   its `Created` field read at maps_sync.go:609 is a SHIPPED ABI BUG
   found by Codex r34: bytes [16:24] hold `SessionID` in the current
   padded ABI, bpf_session_value.go:75, with `Created` at 24-31 —
   flagged for a separate fix issue), idle reaping
   (loop_body/mod.rs:1615 — the `ExpiredSession` struct carries no
   session id, entry.rs:337, so the reaper passes the TABLE ENTRY's
   #5213 id into the close transaction), and terminal/DSCP
   teardown (session_glue/mod.rs:546 → bpf_map/mod.rs:704 — already
   helper-internal) — executes
   INSIDE the Rust helper. (Codex r34's negative inventory is
   adopted as the completeness bound: `userspace_sessions` steering
   state (bpf_map/mod.rs:48-97/600-683), the optional conntrack
   context path (:531-583, no production `Some(ConntrackCtx)`
   caller), fabric-forward, and DNAT maps are NOT session-mirror
   rows, and no separate NAT64/NPTv6 conntrack writer exists.)
   Go-side direct BPF writes become requests over the DEDICATED
   session socket (the channel HA imports already use — no new
   traffic class; the shared control socket is untouched). Operator
   clears (`clear security flow session all`, filtered clears) run
   as CHUNKED IPC with a per-chunk timeout on that socket (AGY r34
   nit 4: bulk clears are allowed to be slow — the latency posture
   is chunked progress with per-chunk deadlines, never a single
   unbounded request, and an operator abort cancels remaining
   chunks).
2. **Bounded admission + explicit refusal + ImportBarrier** (Codex
   r33 finding 1): the per-worker command queues gain bounded
   admission with EXPLICIT REFUSAL (today unbounded,
   bringup.rs:426-432; replacements/deletes bypass the
   distinct-session cap, session_import.rs:108-120/337-345; workers
   drain the whole queue in one loop turn, session_glue/mod.rs:663-704),
   an import sequence, and a per-worker `ImportBarrier` ACK — the
   two-phase owner-export pattern (enqueue under `ServerState`,
   release the global mutex, wait worker ACKs, export.rs:22-66/237-264)
   is the precedent. A refused import returns an EXACT per-key error
   (the import-cap silent return at session_import.rs:115-120 and the
   always-successful handler response at sync_session.rs:19-32 are
   both replaced by exact results). And EVERY WORKER records an
   outcome before its barrier ACK (Codex r35 major 2: today the
   worker handler returns `()`, upsert_synced.rs:18, the table can
   refuse an import, install.rs:310, and `WorkerCommandResults` has
   no import result channel, session_glue/mod.rs:250 — so an
   implementation could mark `Applied` and ACK despite a worker
   refusal; under this rule a reserve/install failure aggregates to
   `Failed` or remains `Pending`, NEVER disappears — the retained
   §5.6 "worker reserve failure drops `UpsertSynced` with an
   accepted not-fed-back asymmetry" text is SUPERSEDED: the
   asymmetry was acceptable only before the applied transaction
   existed, and the outcome channel is now mandatory). Three hardenings (Codex r34
   finding 2): (a) ONE end-to-end deadline — the Go request deadline
   covers the helper's barrier wait plus margin (today export waits
   15s, export.rs:237, Go abandons a session request after ~3s,
   process_control.go:73, and the Rust socket deadline is 5s,
   handlers/mod.rs:44 — incoherent; a LATE commit after Go declared
   failure is an UNKNOWN-RESULT, and any unknown result FENCES the
   receive epoch below); (b) admission RESERVES capacity across
   every affected worker (forward, reverse, and barrier commands,
   with reserved control capacity or separate lanes) BEFORE any
   shared-state or companion-map mutation (today shared state
   mutates before fanout, session_import.rs:133 → :233); and (c)
   any refusal, timeout, or unknown result ABORTS/FENCES the receive
   epoch — no reconcile, no ACK, no hold release. The fence's
   re-drive mechanism is CONNECTION TEARDOWN, not a new wire message
   (AGY r35 finding 2: no NACK frame type exists in the protocol;
   the receiver tears down the sync connection, which triggers the
   sender's existing disconnect re-drive at sync_conn.go:572 with
   the debt machinery re-arming the authoritative prime — a missing
   ACK alone only pends, and survivor re-drive triggers on
   disconnect, not on an ACK timeout, so tens of thousands of
   provisional installs could strand while both fabrics stay
   connected without the teardown).
3. **The applied transaction at the receiver** (Codex r33 finding
   2's first half), with the two ledgers kept DISTINCT (AGY r34
   major 1): (a) `bulkRecv` MEMBERSHIP is still recorded AT DECODE
   for every received key, quarantined or not (the AGY r15 rule —
   reconcile-at-BulkEnd deletes live sessions absent from the
   received set, so decode-time recording is reconcile protection
   and is NOT gated on anything); and (b) the per-key
   INSTALL-CONFIRMATION ledger tracks the helper's exact result for
   each key the import path actually dispatches (today: install
   errors only logged, sync_conn_gen.go:435-490). The `BulkEnd` ACK
   is conditioned on ZERO install-confirmation failures across the
   ledger (a failed key means no ACK and the partial-bulk
   disposition — never reconcile-and-ACK over a silently skipped
   install), while a QUARANTINED key is not an install failure: it
   is a deliberate hold resolved by the quarantine discipline in the
   same serialized pass BEFORE the bulk ACK and sync-hold release
   (the existing rule — the receiver never ACKs while a genuine row
   is unresolved, sync_conn_read.go:240/244). The confirmation
   ledger's terminal outcomes are explicit (Codex r34 finding 3):
   `Applied`, `AlreadyNewer`, `ConfirmedAliasNoop` (an intentional
   non-install — never a failure), `Failed`, and `Pending`; the
   `BulkEnd` ACK requires ZERO `Failed`/`Pending`. A
   `ConfirmedAliasNoop` terminalizes ONLY after P2's purge reports
   (Codex r35 finding 5: the noop can otherwise become terminal
   before the purge of a previously admitted publication completes
   — the current helper deletion returns no result,
   delete_synced.rs:20): the purge's report is one of `deleted`,
   `absent`, or `publication-mismatch-to-newer` (the key is now a
   legitimate newer row — no purge needed); a purge failure is
   `Failed`, and a timeout/unknown result remains `Pending` and
   fences the epoch before reconcile.
4. **Exact-incarnation delete transactions that PUBLISH the close
   inside the commit** (the r32 crux, now statable because there is
   exactly one writer process): every close/delete compares the
   mirror row's stored #5213 id against the closing entry's id under
   the helper's OWN per-key stripe (single process — no
   cross-process arbiter is needed, the two-process writer set that
   killed v15.19 no longer exists). On a match (or absent row), the
   transaction deletes the row AND publishes the close delta INSIDE
   the same commit — a close can never be published for a row the
   arbiter refused to delete (Codex r33 finding 2's policy-
   invalidation trace: Go enumerates rows, the arbiter refuses the
   live replacement's deletion, and Go publishes the close anyway →
   the peer deletes the live replacement; under the transaction the
   refusal suppresses BOTH). On a newer-incarnation mismatch the
   close is suppressed entirely (v15.19's rule, retained). The
   transaction's authoritative predicate is the HELPER'S TABLE, not
   the mirror row (Codex r34 finding 4: B replaces A and publishes
   Open G2; B's mirror write FAILS — mirror absent; a delayed
   Close(A) taking a mirror-absent branch would publish and
   `takeDeleteGenV4` would draw G3 > G2, deleting LIVE B at the
   peer — mirror absence is safe ONLY when no different live helper
   table entry exists for the key, and a mirror-write failure feeds
   the omission machinery, publish_conntrack.rs:141's
   log-and-continue is not silent). EXACTLY ONE close producer
   exists: the helper publishes the close INSIDE the committed
   delete transaction (Go never independently `QueueDeleteV4/V6`s
   for helper-owned rows — v15.21's "Go fires QueueDelete from the
   confirmed result" is REMOVED because it duplicates the helper's
   close into a replacement-killing double, while the helper's
   close already reaches `QueueDelete` through
   daemon_ha_userspace_stream.go:393; Go-INITIATED deletes (policy
   invalidation) are REQUESTS — the helper executes and publishes
   on commit, nothing is published on refusal). The comparison
   identity is named per transaction class: local closes compare
   the NODE-LOCAL `SessionID` (the helper's own allocation);
   imported-row deletes compare the preserved cross-node
   `RTFlowSessionID` (the originator's stable id — the two are
   DISTINCT, types.go:27, and conversion mints the former while
   carrying the latter, daemon_ha_userspace_convert.go:328);
   policy/clear transactions compare the row's stored id in
   whatever domain the row carries.
5. **Refresh discipline** (Codex r32's refresh-restore inverse +
   r34 finding 5's implementability correction): BPF replaces the
   whole value, so "field-targeted" means a SEMANTIC
   read-modify-write UNDER the same per-key stripe, GATED on the
   row's stored `session_id` equalling the refreshing entry's id
   (the refresh sources the id from its own table entry — the
   mirror iterator does not expose it, lookup.rs:501), merging ONLY
   the named fields (`last_seen`, re-resolved `policy_id`, and the
   counter fields) onto the row's current value — never rewriting
   the id or any other field (today the whole cached value is
   written back with `BPF_EXIST`, bpf_map/mod.rs:429/451 — the
   refresh-restore inverse). Counter ownership is singular: only
   the session's OWNING worker's refresh merges counters AND the
   re-resolved policy_id (every worker invokes refresh today,
   loop_body/mod.rs:975, and imports fan out to every worker,
   session_import.rs:233, so replicas SHARE the adopted session id
   and id-gating alone cannot identify the owner — the executable
   predicate is the entry's ORIGIN/ownership marker, evaluated
   before the merge: only the owner merges policy_id and counters,
   Codex r35 finding 6); a replica's refresh touches ONLY
   `last_seen` and applies it MONOTONICALLY
   (`max(current, candidate)` — a replica must never overwrite the
   owner's legitimate counter or policy state, nor drag the row's
   last_seen BACKWARD with its own stale view, AGY r35 finding 3 +
   Codex r35 finding 6). The refresh iterator gains the origin
   projection as an internal signature change (today it exposes no
   origin, lookup.rs:501 — Codex r36 nit 6; the conversion
   distinguishes local/promoted owners from replicas, entry.rs:216 /
   shared_ops.rs:212), and §9 pins the stale-replica regression
   (a replica's older last_seen never overwrites the owner's newer
   one).
6. **Dual-lane deduplication through ONE arbiter** (Codex r33
   finding 5's discovery + r34 finding 6's serialization correction):
   Rust clones every delta into the RPC fallback buffer AND the event
   stream (session_delta.rs:276-317), and Go drains the fallback
   every 5s on a different mutex
   (daemon_ha_userspace_stream.go:254-320) while the event callback
   DISCARDS the sequence (daemon_ha_userspace_stream.go:159) — so a
   fallback Close (seq 11) could pass dedup, stall, an event Open
   (seq 12) pass and draw `G_new`, and the stalled Close resume and
   draw `G_del > G_new`, killing the replacement. The rule is ONE
   ARBITER covering source admission, high-water update, AND the
   #2170 generation draw as a single critical section per frame on
   EITHER lane (the dedup check and the generation draw can never be
   split by a stall) — and the arbiter is explicitly GO-SIDE (AGY
   r35 finding 1: an IPC critical section spanning the Rust-Go
   boundary per frame is not implementable; the arbiter is a single
   Go mutex wrapping BOTH the event-stream callback path AND the
   fallback-buffer drain, fed by the Rust-carried ordering tuples,
   evaluating them against the Go per-worker high-water and drawing
   the #2170 generation inside the same critical section). The ordering tuple is carried on BOTH lanes —
   `(worker_id, per-worker source sequence, helper incarnation /
   table epoch)` — as ADDITIVE OPTIONAL fields per the #1961
   additive-wire precedent (the JSON fallback today has only
   `worker_id`, binding.rs:1147, and the binary payloads carry no
   source sequence or epoch, session_sync.rs:15; the header sequence
   is a process-global transport sequence allocated after the
   fallback clone, wire.rs:175 — §6's "no wire change" statement is
   REVISED to additive-optional-fields; a peer that does not
   advertise the capability disables the fallback lane ENTIRELY, the
   safe degradation — no duplicates are possible when only one lane
   runs). The high-water is preserved across an ordinary event-
   stream reconnect; a helper INCARNATION rides both
   lanes and the watermark resets ONLY after validating a new
   incarnation (a reset without validation admits delayed
   pre-reconnect frames; retaining across a helper restart drops
   genuine new low sequences). The incarnation is NORMATIVELY a
   DAEMON-ISSUED monotonic generation (or collision-resistant
   nonce), established at the barriered handoff and bound to the
   currently validated helper instance on BOTH lanes (Codex r35
   finding 4 + r36 nit 5 + r37 nit 5: Rust source sequencing
   restarts at zero, event_stream/mod.rs:261/275, and status
   exposes only PID/start time, control.rs:141 — a helper-local
   boot counter would let a retained (E1,100) reject a genuine
   restarted (E2,1), and §9 pins exactly that case: restarted
   (E2,1) is ACCEPTED after retained (E1,100)); it is never a
   helper-local boot counter, and every incarnation advancement
   emits ONE info-level log marker carrying BOTH the old and new
   generation IDs (`G_old -> G_new` — helper restarts must be
   traceable from production logs, AGY r37 nit 2 / r38 nit 2).
   And a reconnect's barriered handoff
   FLUSHES/INVALIDATES the worker's pending fallback buffer (AGY r34
   minor 2). Go draws #2170
   generations in consumption order inside the arbiter, so with both
   lanes serialized the [Close, Open] order yields `G_del < G_new`
   and the tombstone loses by construction. Cross-worker migration closes are gated by
   the table epoch bump (retained from v15.20: every full snapshot
   replan/teardown, worker-count/queue/RSS change, link-cycle
   stop/rebind, and helper restart bumps the epoch — reconcile tears
   down the complete worker set, reconcile/mod.rs:330-398, and each
   such event is an epoch boundary; a worker-local pre-epoch close
   is suppressed).
7. **Alias provenance — STICKY lineage, not origin** (Codex r33
   finding 6's correction + r34 finding 7's promotion leak): imported
   rows carry explicit provenance, but the origin field is NOT
   sufficient — promotion overwrites `SyncImport` with
   `SharedPromote` (promote.rs:99), demotion writes it back
   (shared_ops.rs:161), and the export's `is_peer_synced` exclusion
   (export.rs:107) does not match `SharedPromote` (entry.rs:242), so
   an old-peer alias that was timeout-admitted and later promoted
   would export to a NEW capable peer as canonical. Alias lineage is
   therefore ORTHOGONAL STICKY metadata preserved across promotion,
   demotion, replication, and reconciliation (never recomputed from
   origin), in TWO STAGES (Codex r36 major 2 — the missed second r35
   MAJOR: marking only CONFIRMED aliases lets a timeout-admitted
   suspect promote and export as canonical — the legacy alias copies
   the base value exactly, daemon_ha_userspace_convert.go:399, and
   `SharedPromote` is exportable, export.rs:114 — while marking
   EVERY suspect permanently would suppress genuine self-NAT/NPTv6
   export beyond the priced delay): (a) `alias-suspect` is
   PROVISIONAL — set at quarantine insertion AND at
   timeout-admission for every signature-matching row, sticky like
   the permanent mark, and suppressing export WHILE UNRESOLVED; and
   (b) `alias-lineage` is PERMANENT — set on alias CONFIRMATION,
   suppressing export for the row's lifetime (subject to the P1/P2
   purge). The suspect mark clears ONLY through a DEFINITIVE
   verdict (Codex r37 major 2: the 5-second incremental window is
   NOT definitive — a lost-base alias copies the base value
   exactly, daemon_ha_userspace_convert.go:399, so "no sibling
   base present" at the timeout proves nothing, and clearing there
   would reproduce the alias-only → timeout → clear → import →
   promote → export trace): the ONLY clearing verdicts are (i)
   the COMPLETE-PRIME definitive pass (the whole snapshot makes
   the sibling-base relation decidable — a suspect whose complete-
   prime verdict is GENUINE (self-NAT, identity-NPTv6, lost-base)
   clears the mark and exports normally; an alias verdict
   transitions it to the permanent mark), or (ii) the row's OWN
   close (mark and row die together). A timeout-admitted suspect
   therefore remains `alias-suspect` — UNRESOLVED — and OWES a
   definitive proof: the receiver requests a complete inbound
   prime for it via the prime-REQUEST field (a stable connection
   may never run another authoritative bulk — the normal sweep
   sends individual frames, sync_conn_sweep.go:142 — so the debt
   is explicit, with the fence cycle as its bound: overdue, the
   receiver fences for it), and a suspect STILL UNRESOLVED at any
   export evaluation keeps the suppression (conservative — every
   export path skips a marked row with the skip counted; the
   terminal bound is the session's own lifetime, the documented
   residual). The debt is TWO SEPARATE DEBTS with separate
   terminals (Codex r40 major 3: a genuine both-empty transition
   with the SAME legacy peer can never discharge the alias-proof
   debt — every snapshot from that peer is permanently
   framing-only): (i) the sender delivery/ACK debt (the existing
   authoritative-prime debt) discharges on `BulkEnd`-ACK per its
   own machinery; and (ii) the RECEIVER ALIAS-PROOF DEBT (the
   suspects' owed definitive proof) discharges ONLY on a
   capability-advertising definitive snapshot or the suspect
   row's own close — a legacy both-empty transition discharges
   (i) per today's interop while (ii) persists until the peer's
   capability is first learned (which forces the fresh capable
   prime). Every export path sees the marks:
   the mirror value gains a
   provenance bit (the `xpf_conntrack.h` ABI has no provenance field
   today — additive per #1961) OR an exact lifecycle-managed side
   index (same lifetime as the row, updated by the same transactions)
   is consulted by the Go bulk and sweep (sync_bulk.go:95 /
   sync_conn_sweep.go:137 filter only ordinary row fields today);
   the helper-side export skip of EITHER mark is counted with its
   own explicit counter/label (the §5.8 taxonomy names the Go-side
   quarantine counter; the export skip is a distinct event and
   gets a distinct helper-side counter covering both
   `alias-suspect` and `alias-lineage` skips — AGY r37 nit 1).
   The alias quarantine,
   decode-time base-identity index, timeout-admission, and P1/P2
   provisional purge remain as the LEGACY-gated disciplines for
   mixed-version cells and transition-era rows (the new+new cell's
   negotiated omission keeps zero alias frames on the wire; the
   machinery's steady-state purpose is the mixed-version and
   timeout-admission transitions, and alias-lineaged rows are excluded
   from any future table-truth export by provenance).

#### 4.0.2 Consequence map for the surviving §5.x machinery

- **The mirror is now CONSISTENT BY CONSTRUCTION** (sole writer +
  exact-incarnation transactions + refresh discipline): the v15.15-
  era V1-V4 bulk-callback re-read machinery SHRINKS to the Go-side
  known-stale omission check — with the omission DECISION bound to
  durable copy-time identity (Codex r34 finding 8: batch iteration
  copies 256 rows before callbacks, maps_session.go:231, and a
  consumed Close deletes the generation record, so absence is
  indistinguishable from cold-start/first-sight/overflow, and
  Close(A)-then-Open(B) leaves B's generation over a copied A —
  key presence/absence cannot decide): the bulk's batch copy binds
  (key, publication id, recorded generation) AT COPY TIME, and the
  callback omits the frame only when the CURRENT recorded
  (publication id, generation) differs from the copy's binding; a
  Go-consumed Close between copy and callback advances the binding
  and the frame is omitted, while a legitimately untracked row
  (first sight, identical binding) is sent. Close-less mutation
  windows (the maps_sync startup cleanup) are inside the same
  transaction inventory, not a claimed impossibility.
- **The failed-delete omission index** (v15.19) becomes EXACT:
  delete failures are per-key results from the helper's transaction
  (rule 2/4), reported on the session socket; the Go-side omission
  set is fed by exact results, not by inferring from syscall
  silence; its overflow arms the out-of-sync latch + debt — and the
  debt's recovery source is SELECTED and made authoritative (Codex
  r34 finding 9: `doBulkSync` scans the dirty mirror — the very rows
  whose deletes failed — and the helper's current table export is
  only Open deltas with no absence reconciliation, export.rs:143):
  the authoritative recovery source is the HELPER's owner-RG
  snapshot, EXTENDED to (i) include every valid local/promoted row
  (`SharedPromote` provenance included — today the export excludes
  peer-synced origins), (ii) exclude alias-lineaged and stale rows
  (rule 7's sticky lineage), and (iii) carry full BulkStart/BulkEnd
  absence-reconciliation framing (the receiver reconciles exactly
  as with a mirror bulk). Debt guarantees acknowledgement of bytes;
  this makes the bytes themselves authoritative.
- **P2 (exact-publication alias purge)** executes INSIDE the helper
  (rule 4's transaction with publication identity) — the
  cross-writer atomic seam that v15.19 could not state exists by
  construction under sole-writer. The ownership is settled ONE way
  (Codex r34 major 11: the retained §5 text placing P2's
  read-compare-delete on Go's serialized receiver loop under
  SessionStore locking is REMOVED — the helper owns the purge), and
  the purge carries an explicit publication exception: deleting a
  receiver-local sync-imported alias NEVER emits a Close back toward
  the canonical owner (the local-only delete shape,
  delete_synced.rs:20).
- **Carry-forward + reconciliation hold + fenced inbound re-prime
  are RETAINED** (the bulk still iterates the mirror — a consistent
  mirror now — and the Open-publish window between Go's delta
  install and the mirror row remains a real, if sole-writer-bounded,
  window); the fenced re-prime gains the one-bit additive
  prime-REQUEST protocol field (Codex r31 finding 3/r32 finding 4),
  and the old-peer fallback is proven rather than assumed (Codex r34
  finding 10 + r35 blocker 1: an old peer ignores the field, and its
  cold-prime arms only on both-slots-empty, sync_conn.go:244/480 —
  and dial ownership is address-selected, sync_conn.go:12/319, so a
  fencing node that is the NON-INITIATOR cannot prevent the old peer
  from redialing one fabric before the other clears (the initiator
  retries every second, sync_conn.go:435; the non-initiator always
  accepts inbound, :388). The rule is therefore an ADMISSION fence
  held THROUGHOUT the quiet interval, in BOTH directions: the
  fencing side refuses authenticated inbound connections AND
  suppresses its own outbound dialing on both fabrics until the
  interval exceeding the peer's disconnect-detection bound (the
  heartbeat/keepalive timeout) has elapsed — only then does it
  admit/dial, so the peer provably observes both slots empty before
  any new connection arrives; the dual-slot race — one fabric
  redialed between the two disconnect callbacks — is excluded by
  the fence, not by dial timing alone. The refusal is at the
  TRANSPORT level, not the post-auth install verdict (Codex r36
  blocker 1: an installConn-time refusal still lets both endpoints
  complete setup and install LOCALLY first, sync_conn.go:100/130 /
  sync_auth.go:329 — so a retry begun within one disconnect bound
  of fence expiry could still occupy an old-peer slot when the next
  connection is admitted, and installConn would observe a nonempty
  registry and never arm needColdPrime, sync_conn.go:248/278; and a
  briefly both-empty old peer can complete a small bulk WRITE —
  BulkEnd written = success without ACK on the old implementation,
  sync_bulk.go:169 / sync_conn.go:194 — clearing its latch with the
  sticky `outboundBulkAcked` suppressing survivor re-drive,
  sync.go:479 / sync_conn.go:572). During the quiet interval the
  fencing side therefore refuses at the TRANSPORT — the listener
  is closed / SYN-level refused — so NO NEW setup completes (an
  old peer needs no protocol change: its connect(2) simply
  fails). Listener closure alone is NOT sufficient (Codex r37
  blocker 1: `Accept` returns a child before `beginSetup` tracks
  it, `finishSetup` removes the child from tracking before
  `installConn`, and `Stop` closes listeners, registered slots,
  and setup children SEPARATELY, sync_conn.go:349 — an
  already-accepted pre-install child survives listener closure,
  and the old unkeyed initiator installs it LOCALLY immediately,
  sync_auth.go:329, leaving the old peer's registry non-empty
  after quiet expiry). The fence therefore GENERATION-BINDS the
  whole admission path: every accepted/dialed child is stamped
  with the current fence generation AT `Accept`/dial completion;
  fence engagement KILLS every pre-fence child (tracked setup
  children AND accepted-but-untracked ones) BEFORE the quiet
  interval's drain clock starts (the interval starts only after
  those children are dead, not at listener closure); and a child
  whose stamp predates the current fence generation is REJECTED
  at every subsequent stage (`beginSetup`, `finishSetup`,
  `installConn`) — a stale child resuming after fence release is
  never stamped as a current admission. The two stalls are §9-
  pinned directly (`Accept→beginSetup` and
  `finishSetup→installConn`). And the fenced window itself is
  accept-proof (Codex r38 blocker 1: engagement advances the
  generation first, so a child accepted AFTER the advance is
  stamped with the CURRENT generation — the sweep kills only
  pre-fence children, the stale check rejects only stamps
  predating the current generation, and such a child stalled
  before `beginSetup` would resume after release and pass every
  check; the existing sweep snapshots and unlocks before closing
  sockets, sync_admission.go:111, and the Accept→beginSetup
  interval is exposed, sync_conn.go:390/409). The rule is
  two-part: (i) while the fence is ENGAGED, `Accept` itself
  REFUSES the child atomically (no stamp is issued — a fenced
  accept can never exist, let alone stall), and (ii) the fence
  advances the admission generation AGAIN AT RELEASE, after
  listener quiescence and a final sweep, so any child that
  somehow obtained a mid-window stamp is stale at release;
  §9 pins accept-after-sweep-start → resume-after-release.
  With pre-fence children dead,
  fenced accepts refused atomically, and
  no new setup completing, NO install happens on either side
  during the interval; the interval starts only after the
  pre-fence children are dead, covers the peer's
  disconnect-detection bound
  after the last transport-refused attempt (any already-installed-
  but-dead connection drains within the bound), and is
  parameterized as `quiet_interval = 2.5 × keepalive_timeout`
  (e.g. 7.5s for a 3s bound — jitter-safe, AGY r36 nit 2, joining
  the implementation parameter summary); a fixed interval sufficing
  because no refusal can be "completed past" — there is no
  post-auth race to restart against (and restarting on every
  refusal would livelock against the 1s retry). The interval's
  DERIVATION is honest about the legacy no-heartbeat-ACK peer
  (Codex r38 blocker 2: `receiveLoop` increments missed heartbeats
  only after `peerHeartbeatAckEver` becomes true — otherwise it
  keeps sending and continues INDEFINITELY, sync_conn_read.go:27,
  and the rolling-upgrade regression requires a no-ACK peer to
  remain connected past the silence limit, sync_test.go:4655/4736 —
  so if our C0 close notification is delayed or lost, the legacy
  initiator RETAINS C0 and never redials while its slot stays
  registered, sync_conn.go:446, and listener refusal cannot kill
  C0 because the retry never occurs). The both-empty proof is
  therefore two-mode: (i) for any peer whose disconnect-detection
  bound is known (current peers and any peer that has ever ACK'd),
  the interval-derived proof stands — the peer's own read-path
  teardown of C0 fires within the bound once our close starves its
  retry stream; and (ii) for a legacy no-ACK peer the completion
  condition is CAPABILITY-GATED, not merely observed (Codex r39
  blocker 1: `BulkStart` carries only an epoch, sync_bulk.go:65 —
  connected force-resync and survivor re-drive also initiate bulks
  without a both-empty transition, sync_conn_sweep.go:111 /
  sync_conn.go:572; and the no-heartbeat-ACK cohort PREDATES the
  #5085 lossless-bulk fix — heartbeat ACK landed 63ab422cf,
  lossless authoritative bulk landed 52fc4a513 — so the legacy
  peer's window is the historical LOSSY one: async lossy export
  plus empty markers, sync_bulk.go:26, pinned by
  sync_bulk_override_5085_test.go:57; an old sender can write an
  incomplete window, return success after BulkEnd, and clear its
  needColdPrime, sync_bulk.go:183 / sync_conn.go:194). The rule:
  a bulk window from a NON-capability-advertising peer is
  FRAMING-ONLY — it may install frames (today's rolling-upgrade
  interop, unchanged and not worsened) but it NEVER clears alias
  lineage or suspect marks, NEVER drives the definitive alias
  resolution pass, and NEVER releases the reconciliation hold for
  lineage purposes (the definitive pass and every lineage clear
  run ONLY against capability-advertising senders' snapshots; a
  legacy window is non-definitive by construction and the plan
  does not pretend otherwise). Authority is bound PER WINDOW
  (Codex r40 blocker 1: the §5.6 rules — every quarantined entry
  resolves at its own BulkEnd, P1 runs at every completed
  BulkEnd, §9 repeats both — predated the capability gate and
  would force resolution on a non-authoritative window): each
  window's authority class is recorded AT ITS `BulkStart` from
  the peer's capability state at that moment, so a mid-window
  capability change neither retro-authorizes nor corrupts it;
  and a NON-CAPABILITY window's resolution is DISPOSITION-ONLY
  (the quarantine's confirm-vs-admit disposition runs as today —
  provisional admission into the import path — but every admitted
  suspect KEEPS its `alias-suspect` mark UNRESOLVED: no
  confirmation, no purge, no clear, and the definitive pass does
  not run — while a genuine row imports normally, so today's
  table never regresses for self-NAT/NPTv6). The capability
  advertisement moves OFF the periodic ticker onto an ORDERED
  PRE-DATA send (the bootstrap defect: the ticker fires every
  5-10s with state initially UNKNOWN, while the connection path
  starts cold-prime IMMEDIATELY, sync_conn.go:130 — a new↔new
  first window could complete before any advertisement): the
  ordered send contract is handshake → capability frame → ANY
  bulk or delta frame, so a new↔new window is never authority-
  less, and UNKNOWN is treated as non-capable (safe default).
  And when capability is FIRST LEARNED mid-connection, the
  receiver forces a FRESH CAPABLE PRIME (a prime-REQUEST the
  capable peer answers — the suspects held under framing-only
  windows resolve at the first CAPABLE definitive pass; the
  prime debt coalesces across them). The receiver's ACK and VRRP
  hold-release behavior toward legacy peers is TODAY's behavior,
  unchanged — the pre-#5085 lossy-window exposure is inherited
  and documented, not created here; and a missed
  per-bulk receive deadline RE-FENCES (each cycle's terminal is
  honest, not proof-based — see below), with
  the readiness timeout as the terminal bounded release — stated
  with full honesty about what is NOT plan-bounded (Codex r39
  blocker 2, with a factual correction owned: the
  `sync_protocol.go:59` deadline cited above is a two-second
  WRITE deadline, not a read deadline — there is NO read-side
  detector for the no-ACK cohort by design: missed-heartbeat
  accounting is disabled until an ACK has been seen,
  sync_conn_read.go:27, the compatibility regression requires
  the connection to stay alive past the silence limit,
  sync_test.go:4655, and while C0 stays registered the initiator
  never redials, sync_conn.go:446 — so for the retained-C0
  trace, NOTHING plan-bounded kills C0; no detector exists by
  design. The terminal is a FENCE-OWNED, DISCONNECTED-ELIGIBLE
  degraded release (Codex r40 blocker 2's three code facts: the
  production ACK-capable detector is a 10-second read deadline
  with teardown after two misses — ≈20s, sync.go:90 /
  sync_conn_read.go:33 — so a 5-second fence interval cannot
  prove mode-(i) both-empty either; the 5-second readiness timer
  requires `syncPeerConnected` and fires only while connected,
  daemon_ha_sync.go:40/:109, and its regression explicitly pins
  NO timeout release without reconnect,
  session_sync_readiness_test.go:33 — so it is NOT the degraded
  terminal for a disconnected fence; and classic RETH VRRP has
  its own 30-second hold timer, manager.go:351). The quiet
  interval is therefore DERIVED from the peer's actual
  disconnect-detection bound: for ACK-capable peers, the
  read-deadline-plus-two-misses bound (≈20s) plus jitter margin;
  for legacy no-ACK peers there is no such bound (the retained-C0
  honesty above — no plan-bounded kill). The degraded terminal is
  the FENCE's own cycle timer, explicitly disconnected-eligible:
  on expiry it releases the sync hold through the same release
  path the bulk-received callback drives (never the connected-
  only 5s readiness timer, whose no-release-without-reconnect
  regression is preserved intact), with each hold class named —
  the sync-hold release path, the classic RETH VRRP 30s hold
  (manager.go:351), and the private-RG readiness gate — the
  fence's release cannot outlast the applicable class's own
  bound. The debt keeps
  owing the authoritative prime, which any subsequent genuine
  both-empty transition (an OS/TCP failure, the peer's restart,
  or a later real disconnect) eventually discharges; the plan
  does not claim a proof it cannot have). §9 pins
  the no-ACK C0 case with a delayed/lost close notification. The old peer's own
  write-completion clearing hazard is bounded receiver-side: the
  receiver never reconciles or releases the hold without a COMPLETE
  bulk (existing rules), the reconciliation hold protects the
  carried set, and a missed per-bulk receive deadline RE-FENCES
  (the receiver invokes the fence again — each cycle carries the
  same both-empty proof). The refusal's connect failure gives the
  peer's 1s retry immediate feedback (no stall, AGY r36 nit 1).
- **The debt machinery** is retained with one correction (Codex r33
  finding 8's tail): the (epoch → debtGen) pair is recorded BEFORE
  the peer-facing End; page/checksum failure, write failure,
  disconnect, or receive abort preserves the debt; ONLY the
  matching peer ACK clears it — the current write-completion clear
  of `needColdPrime` at sync_conn.go:194-206 gets the same
  ACK-conditioned rule.
- **The stale-close discipline** is the three-layer rule: per-worker
  FIFO order + deduplicated lanes (rule 6) for the common
  same-worker replacement; the table-epoch gate for cross-worker
  migration; and the exact-incarnation transaction (rule 4) for the
  mirror.
- **The Go incremental sweep** keeps its journal-flush and
  delete-overflow duties and its mirror scan (now against a
  consistent mirror); its Open-drop recovery is exact — Go's
  `queueMessage` drop arm already sets `syncBackfillNeeded`
  (sync_conn_write.go:36-49), and the sweep re-sends live sessions
  from the same sole-writer mirror.

### Option (a) — reserve translated identity at admission; PAT the later collider (RECOMMENDED)

Interface-mode becomes "address-only occupancy with preserve-first and an
exact PAT fallback", built ENTIRELY on the shipped #5269 token machinery:

1. **Registry (node-lifetime, OUTSIDE ForwardingState)** — coordinator-owned
   next to the shared session maps (`SessionManager`), cloned into every
   worker (`WorkerSharedDataplane::from_coord`). Never rebuilt on commit;
   one `Arc<PortAllocator>` per egress address. `allocator_for` is ONE
   write-lock `entry(addr).or_insert_with(...)` returning the stored winner.
   Bounded lifetime: apply-time reclamation (address absent from the new
   egress set AND `live_by_flow` empty) + opportunistic reclaim when a
   release empties an absent allocator; a cap of 256 CURRENTLY-RETAINED
   allocators (retained cardinality, NOT ever-created — its own failure
   surface per §5.8); RELEASE is LOOKUP-ONLY (`allocator_if_present`).
2. **Occupancy model (identity-set, no bitmap claims)** — occupancy keyed on
   the FULL reverse identity `(protocol, egress_addr, port, dst_ip,
   dst_port)` (the shipped `AddressOnlyReverseKey`, allocator.rs:178-183):
   same source port to different servers → BOTH preserve; TCP vs UDP same
   numeric port → both preserve; source port < 1024 → preserved (PAT
   candidates drawn ≥ 1024); cross-destination port reuse allowed (the
   Junos-default OVERLOADING posture). The design carries TWO DISTINCT
   tuples per flow (Codex r29 finding 3 — v15.16's canonicalization
   conflated them): the **owner tuple** `(protocol, src_ip, src_port,
   ORIGINAL dst_ip, ORIGINAL dst_port)` is the flow's own identity —
   idempotence, staged-replacement matching, release/rollback, holder
   accounting — and never changes with NAT decisions (a flow re-admitted
   is the same owner flow); the **occupancy tuple** `(protocol,
   egress_addr, translated_port, EFFECTIVE dst_ip, EFFECTIVE dst_port)`
   is the wire-visible reverse identity — collision detection, the PAT
   decision, and reserve/rollback of the translated identity — where
   EFFECTIVE means `nat.rewrite_dst.unwrap_or(dst_ip)` AND
   `nat.rewrite_dst_port.unwrap_or(dst_port)`, mirroring
   `forward_wire_key`/`reverse_wire_key` (session/key.rs:28/94) so the
   occupancy space IS the wire tuple space. Every registry comparison
   that asks "does this translated identity collide" uses the occupancy
   tuple; every comparison that asks "is this the same flow" uses the
   owner tuple (Codex r28 blocker 3 + r29 finding 3: `with_destination`
   changes only the IP, types/mod.rs:280, and today the release/reserve
   sites build with the RAW `key.dst_port` — so `VIP:80` and `VIP:81`
   both DNAT'd to `backend:8080` and interface-SNAT'd would occupy two
   registry identities whose forward AND reverse wire tuples are
   identical; and naively canonicalizing the owner key itself makes
   `H:5555→VIP:80` vs `H:5555→VIP:81` (both → `B:8080`) normalize to
   ONE owner flow, mistaking a collision for idempotent reuse. With the
   split: the two flows keep DISTINCT owner tuples — the second
   admission is a real new flow whose occupancy tuple collides, so it
   PATs — and §9 pins both the VIP:80/VIP:81 composed-DNAT collision
   AND the same-client two-VIP idempotence regression).
   Representability (Codex r30 finding 3): the occupancy tuple is an
   EXPLICIT INPUT to every registry API — computed ONCE at the
   decision point from the NAT decision (where `rewrite_dst` /
   `rewrite_dst_port` live) and passed down — NEVER derived from the
   owner flow downstream (the shipped address-only allocator derives
   destination occupancy from `flow.dst_ip/dst_port` at
   allocator.rs:1727/1740, which would silently re-break the moment
   `flow` carries the original destination). Ownership records are
   keyed `(owner, FULL occupancy tuple)` — the complete
   `(protocol, egress_addr, translated_port, eff_dst_ip,
   eff_dst_port)` — not `(owner, TranslatedTuple)` (which is only
   (ip, port), allocator.rs:108, so a backend-only DNAT change would
   leave the record key unchanged and the staged replacement could
   not hold old and new occupancy simultaneously). And the keys are
   SEPARATE TYPES: the interface registry's owner key is a NEW
   `InterfaceOwnerKey` (original destination); the shipped
   `SourceNatFlowKey` (effective destination) stays EXCLUSIVELY in
   the pool domain whose idempotence/occupancy semantics it already
   serves (source.rs:807/880/1191 and the rollback sites
   poll_descriptor/mod.rs:2201/2313 keep their current meaning);
   NAT64's three sites (nat64.rs:1179/1254/1337) are internally
   consistent and untouched.
3. **Admission mint** (interface branch, nat/source.rs:1226), gated
   `!non_first_fragment && !tuple_unknown` (BOTH probe classes mint nothing):
   - **port-less protocol**: `alloc.reserve_address_only(owner, occupancy, w)` —
     Ok → Matched (address-only); Err → `Unavailable(AllocatorExhausted)`
     (the decision-time composition captures BOTH the owner key and the
     occupancy tuple explicitly for the release/rollback closure — the
     shipped shape saves only the effective-destination `nat_match_flow`,
     poll_descriptor/mod.rs:2201/2269, which cannot carry both,
     Codex r31 finding 4).
   - **port-bearing**: per-step single-mutex CS — (i) idempotent re-entry;
     (ii) identity-mint the PRESERVED tuple → `rewrite_src_port: None`;
     (iii) identity held by a different flow → EXACT PAT probe: capture ONE
     start ordinal from the allocator's atomic cursor, walk
     `start + i mod 64512` LOCALLY (never re-calling the shared cursor
     mid-walk), identity-minting per candidate, at most 64 candidates per
     `live` mutex acquisition with yields between (#4676). A full cycle
     with no success = exhaustion, two modes distinguished by counter
     (§5.8): per-(egress,dst,dport) identity space full, OR the per-address
     `live_by_flow` registry cap (64512) consumed by flows to OTHER
     destinations. ONE mutation-epoch retry (re-walk once if the epoch
     advanced mid-walk); a second failure is documented exhaustion-under-
     churn (the linearizability boundary AGY r3 verified).
   - Preserved and PAT'd tokens share the SAME `address_only` record shape
     and the SAME release/rollback arms. No lock-free pre-claim exists.
4. **No session-index, lookup, flow-cache, or packet-rewrite changes** —
   identities unique per flow ⟹ the bijective fast path is correct; NO
   longer packet-path scan (per the review's guidance). Surface audit
   (verified POSITIVE by AGY r2 + Codex r2/r3/r4):
   `rewrite_src_port: Some(_)` is already generic from pool mode on
   flow-cache descriptors (flow_cache.rs:586), conntrack publish
   (publish_conntrack.rs:197), gRPC render (server_sessions.go:1724),
   RT_FLOW (rt_flow.rs:82), HA conversion (daemon_ha_userspace_convert.go:357
   + protocol_ha.go:57); DNAT composition is internally consistent
   (`merge()` preserves destination rewrites, nat/mod.rs:125, and the SNAT
   allocation uses the effective post-DNAT destination — IP AND port,
   per the §4-option-(a) canonicalization rule,
   poll_descriptor/mod.rs:2201); tunnel-local entries carry
   `NatDecision::default()` (tunnel.rs:565) — no counterexample.

Trade-offs: closes the security hole AND the availability hole; wire change
only for wire-ambiguous flows; (b)'s squatting DoS avoided. Cost: registry +
holder model + §5.7 foreclosure + §5.8 counters.

### Option (b) — reserve-and-reject: fail the later collider closed

Identical machinery minus the PAT probe: identity-mint Err →
`Unavailable(AllocatorExhausted)`. Smallest diff (strict subset of (a)).
Costs: (i) availability loss Junos does not have (same-id ICMP ping pair
hard-fails the second host); (ii) **identity-squatting DoS** (learned or
brute-forced (port, server) squats deny the victim indefinitely) — converting
a confidentiality bug into an availability bug under the SAME attacker
preconditions. (AGY r1 argued (b); AGY r2+ and Codex r2+ endorse (a).)

### Option (c) — status quo + documentation

Keep the collision; document it. Zero diff; keeps a High-severity silent
misdelivery + hijack/squat primitive on a security-labeled issue.
Recommended AGAINST.

**Recommendation: option (a)** — preserve-first identity reservation + exact
chunked PAT probe + port-less fail-closed token + §5.7 foreclosure with
drain. All three reviewers have endorsed (a) since round 2.

## 5. Concrete design

### 5.1 Registry type and placement

```rust
/// Node-lifetime interface-mode SNAT identity registry, coordinator-owned
/// next to the shared session maps (SessionManager,
/// coordinator/session_manager.rs:12), cloned into every worker
/// (worker/launch.rs:130). ONE allocator per egress ADDRESS (never per
/// rule, never per VRF: the reverse lookup namespace is global-by-address —
/// session/key.rs:9, #2387 open).
pub(crate) struct InterfaceNatAllocators {
    map: RwLock<FxHashMap<IpAddr, Arc<PortAllocator>>>, // 1-address each, 1024-65535
    /// §5.7: addresses whose interface mints are quarantined while a
    /// draining pool/NAT64 domain still holds live allocations on them.
    draining: RwLock<FxHashMap<IpAddr, Vec<Arc<PortAllocator>>>>,
}
impl InterfaceNatAllocators {
    /// ONE write-lock entry().or_insert_with() — the stored winner returns.
    /// FALLIBLE (Codex r29 finding 8): None at the 256-retained cap when
    /// no allocator is reclaimable — admission fails closed on that arm
    /// (never exceeds the cap, never evicts live state) with its own
    /// §5.8 counter, exactly like per-destination exhaustion.
    fn allocator_for(&self, egress: IpAddr) -> Option<Arc<PortAllocator>>;
    /// LOOKUP-ONLY release path: None when no allocator exists — never creates.
    fn allocator_if_present(&self, egress: IpAddr) -> Option<Arc<PortAllocator>>;
    /// Apply-time + opportunistic release-time reclamation (absent AND
    /// empty); cap 256 RETAINED allocators. Allocators present in
    /// `draining` are EXCLUDED from reclamation until their drain
    /// completes (live count reaches zero and the drain lifts —
    /// reclaiming a draining allocator would strand the releases that
    /// must still reach it, AGY r22 nit 2).
    fn reclaim_absent(&self, live_egress: &FastSet<IpAddr>);
    /// Teardown: drop ALL Worker markers registry-wide (workers joined,
    /// tables destroyed); records emptied -> freed (§5.6).
    fn release_all_worker_markers(&self);
}
```

### 5.2 Admission mint

`match_source_nat_result_for_tuple` gains `iface_allocs: &InterfaceNatAllocators`
AND the caller's worker id `w: WorkerId` (Codex r29 finding 7 — the
local mint must acquire the `{Worker(W)}` holder, and W exists only in
worker context; both are threaded through
`match_source_nat_for_flow_result_at`
(afxdp/forwarding/nat.rs:104), `source_nat_decision_for_flow`
(poll_descriptor/nat_exception.rs:24), the #6122 probe
(nat_exception.rs:96), and the coordinator test helper
(coordinator/status.rs:556)), PLUS the EFFECTIVE post-DNAT destination
(ip, port) as an explicit input — `with_destination` changes only the
IP (types/mod.rs:280) and today the raw `dst_port` feeds both key
construction and rule matching (source.rs:1191/1206), so the
effective port is plumbed alongside the effective IP rather than
re-derived at each registry site (Codex r29 finding 3's second half).
The #1377 "exactly two fail-closed decision
sites" textual guard counts decision SITES, not signatures — unchanged.
The interface branch:

```rust
if rule.interface_mode {
    let Some(rewrite_src) = (egress addr of the packet's family) else {
        return Unavailable(InterfaceNoEgressAddress);        // #5688, unchanged
    };
    if non_first_fragment || tuple_unknown {
        return Matched(address-only decision);   // BOTH probe classes: mint nothing
    }
    // §5.7 drain quarantine: fail closed while a draining domain holds live
    // allocations on this address (new-mint gate ONLY — reserves exempt).
    if iface_allocs.is_draining(rewrite_src) {
        return Unavailable(for_rule(rule, SourceNatFailureReason::InterfaceOverlapDraining));
    }
    let Some(alloc) = iface_allocs.allocator_for(rewrite_src) else {
        // registry-cap saturation, no reclaimable allocator — fail closed
        return Unavailable(for_rule(rule, SourceNatFailureReason::InterfaceRegistryCap));
    };
    if port_less {
        // occupancy = (protocol, rewrite_src, flow.src_port, eff_dst) — the
        // port-less token keys the reverse identity; w acquires {Worker(W)}.
        return match alloc.reserve_address_only(owner, occupancy, w) {
            Ok(_)  => Matched(address-only decision),
            Err(r) => Unavailable(for_rule(rule, r)),
        };
    }
    match alloc.allocate_interface_identity(owner, occupancy, now_ns, w) { /* §4.3 */ }
}
```

### 5.3 Reserve / release scan semantics (tri-state + provenance + drain + tuple-versioned records)

Every reserve and release scan over the occupancy domains becomes
TRI-STATE per domain (Codex r4 blocker 1 — "not this domain" and "identity
conflict" must never be conflated):

```
enum DomainReserve { NotThisDomain, Owned, IdentityConflict }
```

- A domain answers `NotThisDomain` when the translated address is not its
  own (pool does not contain E; interface registry has no allocator for E
  AND this is not an interface-SNAT import — see the import-driven
  creation rule below).
- A domain that owns the address attempts the reserve: success → `Owned`;
  the identity is held by a DIFFERENT flow → `IdentityConflict`.
- **Import-driven allocator creation** (Codex r30 finding 4's standby
  hole: only local admission called `allocator_for`, while the
  synchronized reserve was lookup-only — a fresh passive standby
  imported peer interface-SNAT rows with NO reservation, and its first
  post-failover local mint created an EMPTY allocator that could
  preserve an already-live imported identity): when the synchronized
  reserve processes an interface-SNAT import for egress E and no
  allocator for E exists, the reserve CREATES it (the same fallible
  `allocator_for` path — cap discipline included) and reserves the
  imported identity, so the standby's registry mirrors the active's
  occupied identities BEFORE any local mint; `NotThisDomain` remains
  for the genuinely-other-domain and drain cases only. §9 pins the
  failover-then-mint collision regression (imported identity held,
  first local mint PATs).
- Scan order pools (active rules) → draining pools → interface registry;
  the scan STOPS at `Owned` and ABORTS at `IdentityConflict` (the import/
  reserve fails closed — never falls through to a second domain, so no
  cross-domain duplicate is possible even mid-drain: Codex r4's
  counterexample — draining pool owns T, interface reserve of the same T
  falls through — dies here: the draining pool answers IdentityConflict and
  the reserve aborts).
- `nat.nat64` decisions BYPASS the source/interface scan entirely (their
  reserve belongs to `reserve_synced_nat64_allocation`,
  upsert_synced.rs:105) — no double-domain token. (Post-#5144 a NAT64 pool
  is never also a source pool, so this is defense-in-depth, not a behavior
  change.)
- The DRAINING vec participates in BOTH the release and reserve scans
  (AGY r4 major 2: a pool edited/removed while draining leaves its
  allocator out of active `rules`; expiring pool flows' releases and
  mirrored reserves must still reach it — flow-keyed discrimination makes
  double-release impossible: a flow's allocation lives in exactly one
  allocator per tuple).
- **Tuple-versioned ownership records** (Codex r5 blocker 1 — one
  `live_by_flow[flow]` record CANNOT represent the staged-replacement
  overlap where T_old and T_new must both be held; allocator.rs:480 keys
  records by `SourceNatFlowKey` alone, and `reserve_flow`'s stale-drop at
  allocator.rs:1671 unconditionally removes+frees the old record). The
  interface registry's allocators key ownership records by
  `(owner tuple, FULL occupancy tuple)` — the owner tuple being the
  original-destination `InterfaceOwnerKey` flow identity of the §4
  split (a NEW type; the shipped pool-domain `SourceNatFlowKey` and
  its effective-destination semantics are UNTOUCHED, per the §4
  representability rule):
  - idempotent re-entry = a hit on the SAME `(flow, translated)` pair
    (unchanged semantics);
  - a flow MAY transiently hold two records (T_old + T_new) during a
    staged replacement — each with its own holder set;
  - release/rollback match `(flow, translated)` exactly (the construction
    already carries both);
  - **the reserve NEVER auto-drops a different-tuple record** (Codex r6
    major 2: `reserve_flow`'s unconditional stale-drop at
    allocator.rs:1671 is NOT inherited — the §5.6 staged protocol drives
    every marker move explicitly at its own steps; a reserve only ever
    inserts/idempotent-hits the `(flow, translated)` record it was asked
    for);
  - **secondary flow index + selection rule** (Codex r6 major 2: the
    admission mint calls the allocator with only `flow` — the translated
    tuple is what is being decided — so a `(flow, translated)`-only map
    removes the idempotent lookup). A `flow -> SmallVec<records>`
    secondary index backs the mint path. Selection rule: a LOCAL mint
    re-entry returns the flow's locally-minted record (in practice at
    most one exists — a local admission is a single decision episode;
    the two-record transient exists only across a RE-SYNC boundary on the
    standby, where no local mint of that flow runs); reserves present
    their tuple explicitly and hit the `(flow, translated)` record
    directly;
  - `max_tracked_flows` counts RECORDS (a mid-overlap flow counts 2 — a
    bounded transient);
  - the per-index drain counter increments per record's authoritative
    `addr_index`.
  Pool allocators are NOT re-keyed: pool records keep today's
  flow-keyed shape and today's free-on-release semantics (pool holder
  tracking remains #6522's own issue). The tuple-versioned shape is a
  property of the allocator instances the interface registry creates.
- `addr_index` becomes AUTHORITATIVE in every address-only mint/reserve
  path (Codex r4 blocker 3: `reserve_address_only` and its roundrobin
  variant currently write `addr_index: 0`, allocator.rs:1770/1874/1809, so
  the per-index drain counter would misattribute an address-only flow on E
  to index 0 = a different address). The mint/reserve paths record the
  chosen address's real index; stale-tuple moves update it. The drain
  probe is then O(1) per-index live count.
- The nine release sites thread the worker's stable `worker_id: u32`
  (`BindingWorker.worker_id`, worker/mod.rs:108-112).

### 5.4 HA / mixed-version

Synced decisions carry `rewrite_src_port` over the existing wire — no wire
change. Mixed-version rolling upgrade:
- new active → old standby: the old standby IMPORTS the PAT'd decision fine
  (generic field — protocol_ha.go:57, daemon_ha_userspace_convert.go:357;
  AGY r1's "mis-parse" claim withdrawn in AGY r2). The old standby never
  RESERVES it (its reserve skips non-pool rules, nat/source.rs:921).
  Post-failover it can admit a no-PAT flow onto the synced tuple —
  collision probability equal to the pre-existing bug's, not worse.
- old active → new standby: the pair the old active admitted collides on
  the standby exactly as on the active; the new standby pre-reserves the
  first and DROPS the second import on conflict (§5.6); post-failover the
  dropped flow re-establishes. Pinned bulk-sync/failover test (§9).
- Verdict: an ACCEPTED, documented rolling-upgrade window bounded by the
  pre-existing bug's probability, closing when both nodes upgrade.
  `SessionSyncProtocol` gating (pkg/upgrade/imageversions.go:162) rejected.

### 5.5 Fragments / ICMP

First fragment carries L4 → normal admission; the forward fragment assoc
(#2562/#5146) stores the decision (with any PAT port) and non-first
fragments consult it; out-of-order non-first-first fragments drop fail-closed
via the #6122 probe; ICMP echo id collision → second id translated through
the #4074 machinery (RFC 5508 §3.1) including incremental checksum.

### 5.6 Holder ownership and transactional reserve (the lifecycle-complete model)

The holder set on each flow's `live_by_flow` record is a PER-SCOPE
COUNTING structure, not a bare set (Codex r7 blocker 2 — two
holder-bearing rows for one flow can coexist in the same scope: a
fabric base+alias pair in the LEGACY window (the new negotiated-
omission path carries no aliases, but the legacy window keeps them —
§5.6), and a locally-installed entry plus its shared-map row across
scopes; a
`FxHashSet<HolderId>` cannot count two rows in one scope, and deleting
either row must not remove the sole marker while its companion remains
reachable):

```rust
struct HolderSet {
    /// worker_id -> count of holder-bearing rows for this record in that
    /// worker's table (locally installed entry + materialized replica +
    /// legacy-window alias entry each count one).
    per_worker: FxHashMap<u32, u16>,
    /// count of holder-bearing rows in the shared canonical map
    /// (base canonical row + legacy-window explicit fabric alias row).
    shared_rows: u16,
}
```

Reverse companions and derived reverse/forward-wire INDEX rows are
holder-neutral. Every acquire adds one unit at its scope; every release
removes one unit at its own scope (per-holder-owner discipline); the
record's identity frees only when `per_worker` is empty AND
`shared_rows == 0`. Saturating-decrement clamp + flow+tuple-keyed release
(a stray decrement can never touch a different flow's allocation).

- **Local admission**: mint inserts `{Worker(W)}` at decision time —
  RESERVE-BEFORE-INSTALL by construction (install-refused aborts roll back
  via the existing rollback sites).
- **Local publication acquires {Shared}** (Codex r4 blocker 5):
  `publish_shared_session` gains the registry parameter and, for FORWARD
  entries whose decision's `rewrite_src` resolves to an interface-registry
  allocator (`allocator_if_present`) with a live record for this flow,
  inserts `{Shared}` into that record (idempotent — the canonical insert
  below). Without this, worker expiry released the only holder
  (loop_body/mod.rs:1625) before the Close-delta removed the shared row
  (session_delta.rs:436) — the early-free shape the holder model exists to
  eliminate. Reverse companions are holder-neutral.
  `remove_shared_session` gains the registry parameter and removes
  `{Shared}` (the canonical row's removal at
  session_delta.rs:436/446, promote.rs:181, session_glue/mod.rs:587/938/945,
  session_import.rs:314/329, local_delivery.rs:91 — the closed inventory,
  SMR r3 M13 including the note that a locally-owned reap reaches removal
  VIA THE CLOSE-DELTA RELAY, not at reap time).
- **Sync import — TRANSACTIONAL at the coordinator**: the coordinator
  pre-reserves the identity (+`{Shared}`) BEFORE `publish_shared_session`
  (ha/session_import.rs:131-137 publishes before fanning worker upserts at
  :233). On identity CONFLICT the import is DROPPED (counted by
  `xpf_userspace_interface_snat_sync_identity_conflict_drops_total` + one
  Debug line) — fail-closed: the standby never holds a session it cannot
  own. Pre-reserve gates `is_reverse`. Bulk-sync replay is idempotent. The
  HA-fidelity DoS (an attacker on the standby's segments squatting a synced
  identity so every refresh import loses) is EXPLICITLY ACCEPTED and
  EXPOSED (Codex r3 major 6: drop is the safer posture;
  quarantine-with-retry adjudicated and rejected — a quarantined session
  still cannot forward at failover but holds table state).
- **Worker-side sync install — RESERVE-BEFORE-INSTALL**: the single
  `install_synced_with_reserve(...)` wrapper = (1) reserve/+`{Worker(W)}`
  (idempotent-hits the coordinator's pre-reserved record); on reserve
  FAILURE → do NOT install (drop the command, count, Debug); (2) install;
  on install refusal → release the just-added holder (rollback). Used by
  ALL THREE sync-family install sites (AGY r3 verified the inventory
  complete): `WorkerCommand::UpsertSynced` (commands/upsert_synced.rs:65),
  `materialize_shared_session_hit` (session_glue/mod.rs:1130),
  `WorkerCommand::UpsertLocal` (session_glue/mod.rs:808).
  **Materialize failure semantics** (Codex r4 major 7 + r5 major 4):
  materialize is not a command, and a `None` lookup return does NOT drop
  the packet — `resolve_flow_session_decision` returning None at
  session_glue/mod.rs:1227 makes the caller treat it as an ORDINARY
  session miss and enter the full cold policy/NAT/admission path
  (poll_descriptor/mod.rs:432/903). The wrapper's reserve-conflict
  therefore returns a DISTINCT `MaterializeConflict` outcome propagated to
  an explicit recycle/drop branch (packet recycles, counted) — never the
  cold-admission path and never the unconditional shared decision
  (session_glue/mod.rs:1128/1146 today).
  **Dropped-command gap** (AGY r4 adjudication): a worker whose
  `UpsertSynced` dropped never installs the entry; failover onto that
  worker takes the standard no-session re-establishment path — no
  confidentiality compromise; a later genuine refresh re-publishes and
  re-queues. The coordinator's `{Shared}` for such an entry persists by
  design ({Shared} rides the canonical row, removed by the peer's
  delete-sync or entry expiry — AGY r4 minor 3). (Codex r35 major 2 /
  r36 minor 3 SUPERSESSION: the "not fed back" acceptance predated the
  §4.0.1 applied transaction — under Rules 2-3 every worker now
  records an outcome before its barrier ACK, and a reserve/install
  failure aggregates to `Failed` or remains `Pending` and FENCES the
  receive epoch; the outcome channel is mandatory, and this gap's
  only remaining shape is the post-fence re-drive, which replays the
  import through the same outcome-recorded path.)
- **Tuple-changing re-sync — STAGED REPLACEMENT protocol on
  tuple-versioned records** (Codex r4 blocker 6 + r5 blockers 1-2):
  - Coordinator: pre-read the canonical row's CURRENT tuple T_old →
    pre-reserve T_new (+`{Shared}` on the NEW `(flow, T_new)` record —
    the tuple-versioned record shape of §5.3 lets T_old and T_new coexist)
    → canonical insert displacing T_old's row → ALIAS SWEEP: remove every
    reverse-index/forward-wire alias derived from the DISPLACED entry
    (reverse_wire/reverse_canonical/forward_wire of T_old — today's
    `publish_shared_session` only inserts the new aliases at
    shared_ops.rs:918-943 and never removes the old tuple's, so a stale
    alias would stay resolvable; this sweep is new and also fixes the
    pre-existing stale-alias residual for any tuple-changing republish.
    The sweep mirrors `remove_shared_session`'s exact conditionals
    (reverse_canonical removed only when `!= reverse_wire`; forward_wire
    only when `!= key`) and is FILTERED against the new entry's aliases —
    a same-tuple refresh (T_old == T_new) sweeps nothing, so the entry
    never loses aliases it still needs (SMR r6 nit 1). The sweep is
    COMPARE-AND-REMOVE ownership-validated (Codex r7 major 4 + r8 major 2
    + r9 major 2 — the current removals delete derived slots by key
    unconditionally, shared_ops.rs:978/987/997, so a third-party
    non-bijective occupant of T_old's slot would be swept; and "key +
    NatDecision" is not a sufficient identity, since a newer
    same-key/same-NAT session can carry a different stable identity, and
    the swept maps store `SyncedSessionEntry`, whose only id field is the
    cross-node RT-flow id (worker/mod.rs:375) — the Go node-local
    SessionID is never transmitted (manager_ha.go:1645) and LOCAL
    publications store `session_id: 0` (poll_descriptor/mod.rs:2569)).
    The ownership identity therefore uses a HELPER-LOCAL publication
    token: `SyncedSessionEntry` gains additive `pub_token: u64` — a
    coordinator-local monotonic counter stamped at publish into BOTH the
    canonical row and every derived index row of one publication
    (helper-internal struct change, NOT a wire/Go change) — and, per
    the §5.6 lineage carrier (Codex r38 major 4), a SECOND additive
    optional field for the alias lineage STAGE (`alias-suspect` /
    `alias-lineage` / clear), which IS carried on the sync wire as an
    additive-optional field (per #1961; an old peer ignores it and
    the receiver treats absence as legacy): Every swept
    removal validates ownership ATOMICALLY under the removing map's own
    lock (the maps lock separately — a third party can replace a derived
    slot between canonical replacement and sweep, so check-then-remove
    across locks is insufficient) against the identity chain: equal
    non-zero `RTFlowSessionID`, else equal non-zero `pub_token`, else
    (token-0 legacy rows only) full `SyncedSessionEntry` equality
    excluding counters — two token-0 rows that agree on every remaining
    field are semantically the same session for routing purposes (AGY r9's
    field enumeration), so removing either is indistinguishable. A
    third-party-displacement test, a same-key/same-NAT/different-id
    replacement test, and a newer-local-publication (session_id 0,
    non-zero pub_token) test pin it — Codex r11 major 3's restore)
    ) → `−{Shared}` on T_old. T_old stays held by its `{Worker}` markers
    (never freed mid-overlap); its canonical row and aliases are already
    unreachable when the marker drops.
  - Worker wrapper: pre-read the existing entry's tuple T_old via a NEW
    read accessor (Codex r5 blocker 1: `entry_by_key` is private,
    session/mod.rs:1093 — add a narrow `translated_tuple_of(key)` accessor;
    `upsert_synced_with_origin` keeps its bool return, AGY r5 nit 2's
    `Option<NatDecision>` return is the optional alternative) → reserve
    T_new (+`{Worker(W)}`) → install (in-table replace makes T_old
    unreachable, session/install.rs:322) → release T_old (`−{Worker(W)}`).
    T_old's record empties → freed, only AFTER it is unreachable on every
    scope that referenced it.
  - Each side decrements only its own marker (SMR r3 M14); cross-site
    windows are bounded by the fanout and are hold-safe direction
    (never free-early).
- **Worker-thread teardown — marker drop** (Codex r4 blocker 4 + AGY r4
  major 1): `stop_and_clear` (worker_manager.rs:141) joins worker threads,
  whose tables drop WITHOUT release routines (worker exit only flushes
  counters + CoS leases, loop_body/mod.rs:1563). After the join,
  `release_all_worker_markers()` drops every `{Worker(*)}` registry-wide;
  records emptied → freed. Path matrix (Codex r4's inventory):
  - `stop_inner(false)` — full reconcile (teardown.rs:80) and bind-
    incomplete rollback (bringup.rs:213): worker tables DESTROYED; canonical
    shared entries SNAPSHOT-PRESERVED (teardown.rs:56) and REPLAYED
    (coordinator/mod.rs:810). Worker markers dropped at join; `{Shared}`
    survives (canonical rows persist); replay re-acquires `{Worker}` via
    the wrapper on the new workers.
  - `stop_inner(true)` — link-cycle stop (coordinator/mod.rs:459) and
    process exit (:471): workers joined (worker markers dropped) AND the
    shared maps cleared wholesale — the clear FIRST iterate-and-releases
    `{Shared}` per forward interface-mode entry (AGY r3 major 2), then
    clears; with both marker classes gone the registry holds nothing for
    the wiped state.
  - Same-plan refresh: worker tables PERSIST — no marker event at all.
- **Fabric forward-wire alias: negotiated sender omission (new+new) +
  receiver-side signature quarantine (legacy window) — Codex r6-r13
  converged design**: HA session sync deliberately exports a
  fabric-redirect session TWICE — the canonical forward key AND a derived
  NAT-translated forward-WIRE alias key
  (`userspaceForwardWireAliasFromDeltaV4`,
  daemon_ha_userspace_stream.go:370/373). Rounds 6-10 established the
  alias cannot live in the ownership model; r11-12 established no
  existing field can carry an exact marker (the cluster codec truncates
  `Flags` to one byte, sync_protocol.go:116/122/231/237); r13 established
  a key-only receiver heuristic cannot disambiguate deletes (a genuine
  direct row and an alias can share one key, and deletes carry only the
  key + a fresh per-key generation, sync_protocol.go:326,
  sync_conn_gen.go:156/263). Codex r13's own direction — "exact delete
  provenance — or negotiated sender-side alias omission" — is adopted:
  - **New+new path: negotiated sender-side alias omission.** The
    receiver advertises an additive "omit forward-wire aliases"
    capability (old peers ignore it — sync continues with legacy
    behavior). The channel must work on UNAUTHENTICATED clusters too
    (AGY r14 minor 1: `performSyncHandshake`, sync_auth.go:331-334, is
    bypassed when no auth key is configured — `handleNewConnection`,
    sync_conn.go:100-137, opens the stream with no setup handshake —
    so the capability rides ONE named contract: an additive periodic
    `syncMsgCapability` frame on a dedicated ticker (period aligned to
    the EXISTING heartbeat/ping ticker interval (5-10s) rather than an
    uncoordinated standalone timer goroutine — AGY r21 nit 1; SMR r18
    nit 2;
    Codex r17 minor 2:
    the transport must be one contract, not alternatives — and NOT a
    handshake field, because unkeyed deployments bypass the handshake,
    sync_auth.go:321) — RE-ADVERTISED PERIODICALLY on the dedicated
    capability ticker ALONE (Codex r16 minor 3 + r19 minor 2 + r20
    minor 2: `sendClockSync` currently runs only ONCE at connection
    setup, sync_conn.go:137; the contract is the dedicated periodic
    ticker, with NO piggyback alternative; the per-peer capability
    state RESETS TO UNKNOWN on every (re)connection)
    — so a lost frame self-heals within one period (Codex r15 minor 2: a
    one-shot frame has no defined UNKNOWN → unsupported transition;
    periodic re-advertisement gives every connection a bounded path to
    capability discovery with no handshake dependency — the
    unauthenticated-cluster case is covered, sync_auth.go:321 bypass).
    The sender's rule is DERIVE-UNTIL-CAPABLE: peers start UNKNOWN and
    the sender keeps deriving (today's exact behavior) until a
    capability frame arrives, then omits from that point on. No
    emission hold is needed: a mid-stream transition only means some
    early aliases flowed, and those are exactly what the receiver-side
    quarantine (below) exists to confirm and drop — the transition is
    safe by construction, and a permanently lost capability simply
    stays legacy (never drops sync). A sender that has learned the
    capability SKIPS the alias derivation entirely at ALL FOUR alias
    branches — V4/V6 open AND V4/V6 close
    (daemon_ha_userspace_stream.go:370/379 upserts, :398/:413 deletes;
    Codex r16 minor 3: the omission gate must cover alias deletes too)
    — zero alias upserts, zero alias deletes on the wire. Nothing is dropped at the receiver, no
    signature is needed, NO collateral exists: genuine self-NAT and
    identity-NPTv6 rows flow normally. The alias's work is done by the
    derived forward-wire index row the base session's own publish
    inserts (shared_ops.rs:943-957) — verified five times independently
    (AGY r9/r11/r12/r13, Codex r9/r10/r11/r12/r13) as serving every
    fabric-return lookup the explicit alias row served. The broken
    synthesized-companion hazard (un-NAT replies to the firewall's own
    address every sweep, shared_ops.rs:750 + nat/mod.rs:106 — a live
    shipped bug) closes wherever the sender omits, with zero receiver
    machinery.
  - **Legacy window (peer does not advertise): receiver-side signature
    QUARANTINE, not blind drop.** The old sender keeps emitting
    canonical+alias rows; the new receiver quarantines suspected-alias
    upserts instead of importing or blind-dropping them:
    - **Signature** (computable at the pkg/cluster decode boundary,
      before bulkRecv bookkeeping, sync_conn_read.go:110):
      forward ∧ sync-derived ∧ SNAT flag set ∧ NOT NAT64 (decoded
      `Nat64SnatV4` present, sync_protocol.go:616 — Codex r13 blocker 2:
      a v4 NAT64 rewrite is padded into a v6 slot and reformatted as an
      IPv6 address, eventstream.go:1350, so a legitimate NAT64 client at
      that address WOULD match the source-only signature — the NAT64
      exclusion is mandatory) ∧ `key.src_ip == decision.rewrite_src` ∧
      (`key.src_port == decision.rewrite_src_port` OR
      `rewrite_src_port == 0`) — full rewritten-tuple equality (Codex
      r13 major 3a: same-address pool/interface PAT and same-IP static
      mapped-port sessions are bijective by port and must NOT match;
      static NAT rewrites address AND mapped port, static_nat.rs:746).
      NO disposition/FabricRedirect gate (Codex r14 blocker 1:
      `userspaceSessionFromDeltaV4/V6` does NOT copy FabricRedirect into
      `SessionValue` — only SNAT/DNAT and FabricIngress survive,
      daemon_ha_userspace_convert.go:357/462 — so the cluster codec
      carries no disposition field at all, sync_protocol.go:114/229, and
      the legacy sender cannot provide one. The priced consequence:
      NON-fabric identity-NPTv6 canonical rows also quarantine and
      timeout-admit — a bounded 5s sync delay for a corner-of-corner,
      not a drop).
    - **Quarantine**: a bounded per-peer map (4096 entries, tunable)
      holding signature-matching upserts, PINNED TO ITS ARRIVAL BULK
      EPOCH. **Overflow is a terminal bulk abort, never an eviction**
      (Codex r16 blocker 1: bulk bookkeeping retains only KEYS
      (sync_conn_read.go:200) and the decoded value is consumed
      immediately, so an evicted frame cannot be admitted later — its
      payload is gone; and blind drop could lose genuine self-NAT /
      identity-NPTv6 rows). On overflow the receiver ABORTS the
      incomplete bulk WITHOUT ACK (no reconcile, no sync-hold release),
      counts the saturation
      (`xpf_userspace_session_sync_alias_quarantine_overflow_total`,
      Go-side), applies a per-peer re-prime backoff, and lets the
      sender's bulk machinery retry — the retry re-drives every row,
      so nothing is lost permanently; a persistently overflowing
      deployment (>4096 fabric SNAT sessions in one bulk) must raise
      the cap, and the saturation counter makes the pressure visible.
      The abort CYCLE cost is priced honestly (Codex r18 minor 3): each
      successful full-disconnect ALSO fires the peer-disconnect/connect
      lifecycle callbacks (sync_conn.go:569/142) — config
      reconciliation plus DHCP and IPsec re-advertisement
      (daemon_ha_sync.go:934) — so a persistently overflowing
      deployment pays REPEATED CLUSTER-WIDE SYNCHRONIZATION CHURN per
      cycle, not merely one cold re-prime; the cap is therefore sized
      at provisioning so genuine fabric-session counts never saturate
      it in steady state (the 4096 default assumes ≤~4k fabric SNAT
      sessions per bulk; larger deployments raise it up front), and the
      overflow counter + backoff are the visible escape hatch for the
      undersized case, not the steady-state plan.
      **The abort recovery contract is a GENERATION-FENCED, ATOMIC
      CLUSTER-LEVEL TEARDOWN with commit-time generation validation**
      (Codex r17 blocker 1: no retry mechanism exists today —
      `BulkSync()` is write-only (sync_bulk.go:169/183/195), connection
      setup clears needColdPrime before any ACK (sync_conn.go:194), a
      missing ACK merely stays in pendingBulkAckEpoch with no
      ACK-timeout retry (sync_conn_read.go:257), and the survivor
      re-drive's `outboundBulkAcked` flag is intentionally sticky
      (sync.go:479). Codex r18 blocker 1: two `Close()` calls do NOT
      guarantee the full-disconnect transition — receive loops remove
      connections independently via deferred callbacks
      (sync_conn_read.go:14), `handleDisconnect` runs full cleanup only
      if both slots happen to be nil at that instant
      (sync_conn.go:483/496), and a reconnect installed between the two
      old disconnect callbacks sees a NONEMPTY registry, so neither a
      full-disconnect edge nor needColdPrime is armed
      (sync_conn.go:244/278). Codex r19 blocker 1: a fence stated only
      at `installConn` is still insufficient — receive handlers
      dispatch frames WITHOUT checking registry membership or
      generation (sync_conn_read.go:91) and those frames can install
      sessions (:109) or replace bulk state (:183), so a handler can
      pass a pre-dispatch check, stall, and mutate state AFTER the
      reset; and a legacy peer's PENDING FIRST FRAME is processed
      BEFORE `installConn` (sync_conn.go:119/130), so an install-gate
      alone cannot stop an old peer from mutating receiver state during
      the fence; and `installConn`'s current result cannot express
      refusal while `handleNewConnection` unconditionally starts the
      receive loop afterward (sync_conn.go:130)). The transition
      contract is therefore:
      (1) **Fence state**: an atomic ABORT-GENERATION counter + fenced
      flag in the connection registry. On any abort (overflow,
      deadline, teardown) the receiver increments the generation and
      sets the fence — one atomic store on the serialized event loop.
      (2) **Admission verdicts**: `installConn` returns
      ADMITTED/REFUSED (its result type gains the verdict; today it
      cannot express refusal). A REFUSED connection is closed
      immediately with NO pending-frame processing, NO receive-loop
      launch, NO clock sync, NO lifecycle callbacks, and NO cold-prime
      work (Codex r19: `handleNewConnection` must become conditional on
      the verdict, sync_conn.go:130).
      (3) **Install-before-dispatch**: a connection's pending first
      frame is dispatched ONLY AFTER an ADMITTED installation
      (reordering sync_conn.go:119 → :130), and it carries the same
      generation guard as (4) — so an old peer's pending frame can
      never mutate receiver state during a fence (Codex r19's
      old-peer bypass).
      (4) **COMMIT-TIME generation validation**: every stateful frame
      application on the serialized receiver loop (session install,
      bulk-state mutation, quarantine action) re-checks the frame's
      generation against the current abort generation AT THE COMMIT
      POINT — a frame carrying an older generation, or any frame
      arriving while the fence is set, is discarded at commit (Codex
      r19's pass-check-then-stall race: a handler that passed a
      pre-dispatch check and then stalled can never mutate
      post-reset state, because the commit-time guard re-validates at
      the mutation point, not at handler start). The frame-side
      generation is inherited from the CONNECTION SLOT that delivered
      the frame (each slot is stamped with the abort generation
      current at its admission — SMR r20 nit 2), so no per-frame
      generation field is needed on the wire; one atomic load per
      commit on the already-serialized loop, not a lock. The guard
      compares a frame's SLOT-LINEAGE generation against the abort
      generation relevant to THAT slot's lineage, not the global
      maximum — with admissions now advancing the counter too (AGY r25
      blocker 1's discipline (i)), a routine new admission elsewhere
      must NOT poison live slots (SMR r26 clarification).
      (2b) **Stamp-and-enqueue admission**: the ADMITTED verdict's
      atomic unit is BOUNDED to (i) stamping the slot with the current
      abort generation and (ii) ENQUEUEING generation-bound setup
      intents (receive-loop launch, clock sync, lifecycle callbacks,
      cold-prime) — microseconds, no I/O, never the tail itself (Codex
      r21 blocker 1: the tail contains synchronous clock I/O, replay of
      up to 10,000 journal entries, and `doBulkSync()` walking every
      owned session with a fresh 2s write deadline per frame
      (sync_conn.go:132/137/141/194, sync_bulk.go:92/133,
      sync_protocol.go:59) — running it inside the arbiter is
      effectively unbounded in cardinality and backpressure; running it
      under `s.mu` is a documented self-deadlock
      (`BulkSync → getActiveConn` re-enters `s.mu`, sync_conn.go:588);
      and there is no global serialized receiver loop to run it on —
      each connection launches its own receiveLoop, sync_conn.go:132,
      sync_conn_read.go:14, sync_conn_gen.go:381). The intents execute
      OUTSIDE the arbiter on the normal async paths, and each intent
      is GENERATION-BOUND (stamped with the admission generation and
      its slot) and revalidates that binding at its own effect point:
      a stale intent (generation advanced, slot detached, or fence
      set) is CANCELLED before producing effects. Cancellation is only
      half the contract — the effects themselves are classified by
      their reversibility (Codex r22 blocker 1: a generation check
      before a write cannot undo a frame already accepted by TCP, and
      "treating completion as stale" cannot reverse externally visible
      work; and there are two concurrent fabric receive loops, not one
      global serialized commit loop, sync_conn_gen.go:64):
      (i) **Session frames / bulk writes** (`BulkSync` writes
      BulkStart, every V4/V6 session, BulkEnd —
      sync_bulk.go:81/95/133/169, each with its own 2s deadline,
      sync_protocol.go:59): the pre-write generation check STOPS
      further frames after an abort (that part is effective), and
      frames already written are ACCEPTED as individually-valid
      PROVISIONAL installs — each is a session that existed in the
      sender's authoritative snapshot at send time, and the peer
      installs session frames immediately (sync_conn_read.go:109).
      A partial bulk is NEVER ACKed and NEVER reconciled and NEVER
      releases the sync hold (BulkEnd missing → no ACK,
      sync_conn_read.go:205) — its provisional installs stand until
      the NEXT COMPLETE authoritative bulk's reconcile converges them
      (the reconcile is what deletes stale rows; a partial bulk never
      triggers it). Every incomplete bulk's lifetime is bounded by
      the per-bulk RECEIVE DEADLINE (the required new behavior from
      the epoch-death rules), at which the incomplete bulk aborts
      without ACK and its pinned quarantine entries drop fail-closed.
      This is the named partial-bulk disposition: provisional, never
      ACKed, never hold-released, deadline-bounded, converged by the
      next authoritative reconcile.
      (ii) **Callbacks** (`OnPeerConnected` — carries no generation
      today, sync.go:419, and fires externally visible work,
      daemon_ha_sync.go:934): the intent binds the admission
      generation and revalidates BEFORE TRIGGERING (a stale callback
      intent is cancelled with no externally visible work). The
      callback's work splits into two classes (Codex r23 blocker 1):
      (a) the CONVERGENT reads — config reconciliation, DHCP lease
      sync, IPsec SA sync (`d.clusterConfig()`,
      `d.nudgeDHCPLeaseSync()`, `d.nudgeIPsecSASync()`,
      `d.reconcileConfigSyncToPeer("peer-connect")`,
      daemon_ha_sync.go:934-957) — which evaluate LIVE daemon state at
      execution time (verified: none use frozen verdict-time
      snapshots), so a completed-but-stale callback of this class
      installs current state, which is by definition not stale; and
      (b) the DAEMON LIFECYCLE MUTATIONS
      (`onSessionSyncPeerConnected`, daemon_ha_sync.go:934 → :51/:68/:81)
      — storing `syncPeerConnected=true`, advancing the connection
      epoch, resetting heartbeat-suppression state, clearing
      bulk-prime flags, arming the readiness timer — which are NOT
      convergent reads and are NOT ordered today: the concrete race is
      the intent validating and launching, the abort advancing the
      generation and the disconnect callback storing
      `syncPeerConnected=false` (daemon_ha_sync.go:109), and the
      already-launched connect callback storing it back to TRUE.
      Class (b) mutations therefore use ONE LINEARIZABLE COMMIT
      MECHANISM — generation-tagged compare-and-swap with
      MONOTONIC-ADVANCE semantics — not independent validation plus
      stores (Codex r24 blocker 1: a check-then-store split lets the
      detach land after validation and before `syncPeerConnected.Store(true)`,
      recreating the exact connect-after-disconnect race it was meant
      to close; and the asynchronously launched DISCONNECT callback was
      not symmetrically guarded at all — a stale disconnect could store
      `false` after a newer connection stored `true`). Two disciplines
      make the CAS actually linearizable (AGY r25 blocker 1, with the
      exact counterexample: slot C1's abort increments the counter to
      g and its disconnect callback binds g; replacement slot C2's
      admission READS the same g without incrementing, so its connect
      callback ALSO binds g; if C2's connect commits `(g, true)` first,
      C1's delayed disconnect callback still passes `g >= g` and
      overwrites the live state with `(g, false)` — an equal-generation
      stale write flipping active state):
      (i) **STRICTLY ORDERED EVENT TAGS `(abortGeneration,
      lifecycleSequence)` assigned AT THE TRANSITION'S COMMIT POINT**
      (Codex r25 blocker 1 — discipline (i)'s fresh-generation draw is
      NOT sufficient on its own: the abort advances to G and its
      disconnect binds G; the replacement's ADMISSION then draws G+1 —
      but if the admission's draw happens BEFORE the disconnect event
      is admitted, the disconnect's tag and the connect's tag can
      still interleave incorrectly; and incrementing a generation
      INSIDE the callback is no solution either — a delayed callback
      could "forge ahead" by obtaining a newer generation at execution
      time). Every lifecycle event is therefore tagged with a TUPLE:
      the abort generation of its lineage plus a per-generation
      lifecycle SEQUENCE number assigned atomically when the EVENT is
      admitted onto the lifecycle queue (never when the callback later
      executes) — so tags strictly order every event (abort, admission,
      disconnect, bulk-received, bulk-ack-received, AND
      readiness-timeout — the complete event inventory, Codex r26
      blocker 1) by construction,
      and non-monotonic values (true → false → true) remain free
      because the tags, not the values, advance. The lifecycle queue's
      admission point is the single place tags are minted, so no
      callback can forge ahead; and
      (ii) **STRICT-INEQUALITY TAG CAS FOR VALUE-FLIPPING MUTATIONS
      WITH EFFECTS INSIDE THE COMMIT UNIT** — for fields whose
      semantics are connected-state flips (`syncPeerConnected`,
      priming flags, and the bulk-ack flags
      `outboundBulkAcked`/`bulkEverCompleted`, sync.go:478-479), a mutation
      commits only if its event tag is STRICTLY GREATER than the
      currently stored tag for that field, so even an equal-tag stale
      write can never flip active state. And because a per-field flag
      CAS cannot protect the callbacks' EXTERNAL EFFECTS (Codex r25
      blocker 1's second half: a stale bulk-received callback can race
      after a newer lifecycle transition and still stop the readiness
      timer, release the VRRP sync hold, and mark sync ready,
      daemon_ha_sync.go:90), a FAILED/STALE event admission SUPPRESSES
      ALL ASSOCIATED EFFECTS ATOMICALLY: the safety-critical effects
      (timer stop, VRRP sync-hold release, sync-ready marking) execute
      only INSIDE the committed lifecycle event — the same commit unit
      that writes the flag performs the hold release, so a newer
      transition can never interleave between the flag write and the
      release, and a stale event never produces any effect at all.
      Value-nonmonotonic transitions
      (true → false → true) remain free — the CAS orders by
      generation, not value.
      The READINESS-TIMEOUT event is a lifecycle event, not a side
      channel (Codex r26 blocker 1): today the readiness timer's
      expiry callback independently validates `timerGen`/
      `syncPeerConnected` and then calls `SetSyncReady(true)`
      (daemon_ha_sync.go:40-46) OUTSIDE the tag/commit discipline —
      and `Timer.Stop()` cannot retract a callback already executing
      (daemon_ha_sync.go:19), so a timer that passes its checks, then
      stalls while a newer disconnect/cold-start transition commits
      readiness false, resumes and marks readiness TRUE — the exact
      stale-effect race rules (i)-(ii) close for the callback events.
      The rule: timer EXPIRY only ENQUEUES a transition-tagged
      readiness-timeout lifecycle event onto the same serialized
      lifecycle queue (minting its `(abortGeneration,
      lifecycleSequence)` tag at admission like every other event);
      the event's commit unit re-validates the arming generation and
      connected state AND performs `SetSyncReady(true)` — so a
      readiness flip can never commit after a newer transition has
      superseded it, and `stopSyncReadyTimer`'s generation bump plus
      `Timer.Stop()` remains the fast path for the common case while
      the enqueued-event tag CAS is the linearizable adjudicator for
      the race `Timer.Stop()` cannot retract. Timer invalidation is
      also NOT contingent on the session-sync object existing:
      `stopClusterComms` calls `stopSyncReadyTimer` UNCONDITIONALLY
      (moved out of the `if ss != nil` branch, daemon_ha_sync.go:1405
      — Codex r27 minor 3: bringup arms the VRRP sync hold before
      `SessionSync` exists, daemon_run_bringup.go:226, so an
      ss==nil teardown must still bump the arming generation; the
      commit unit's connected-state revalidation is the second gate
      either way). The commit-gate seam is exact (Codex r27 nit 4):
      the expiry event's arming-generation/connected-state reads
      happen BEFORE entry into the serialized commit gate, and the
      gate itself (tag CAS + re-validation + effects) is ONE atomic
      unit — a newer event can never commit while another event is
      inside the gate; the stalled-after-validation scenario stalls
      the event BETWEEN its pre-gate reads and its gate entry, which
      is the only place a newer transition can interpose. A stalled
      expiry event
      whose validation passes and whose commit then loses the tag CAS
      to a newer disconnect/cold-start produces NO effect at all —
      readiness stays false, exactly like a stale bulk-received event.
      Every lifecycle state field in the inventory — `syncPeerConnected`,
      connection epoch, heartbeat-suppression state, bulk-prime flags,
      readiness arming, the bulk-received/ack-received priming flags
      (`onSessionSyncPeerConnected` :51/:68/:81,
      `onSessionSyncPeerDisconnected` :109, `onSessionSyncBulkReceived`
      :90, `onSessionSyncBulkAckReceived` :103, AND the
      `armSyncReadyTimer` expiry event :40 — the complete set,
      AGY r24 nit 3 + Codex r26 blocker 1), AND the bulk-ack lifecycle flags
      `outboundBulkAcked` / `bulkEverCompleted` (sync.go:478-479 — AGY r25
      minor 2; `bulkEverCompleted` is the inbound-direction flag — set
      by an inbound BulkEnd — and `outboundBulkAcked` the outbound ack,
      the code's actual names, Codex r27 nit 5). (Cited line numbers throughout this plan are
      ILLUSTRATIVE snapshot points at the base commit — function/symbol
      names are the primary identifiers and drift slower than line
      numbers, AGY r26 nit 1.)
      Every field in the inventory is stored as a (generation, value) pair
      committed by the CAS under rules (i)-(ii), so a stale
      connect-callback's `true` cannot overwrite a newer disconnect's
      `false`, a stale disconnect's `false` cannot overwrite a newer
      connect's `true`, and an equal-generation write can never flip
      active state — with no check-then-store window by construction
      (the CAS IS the commit point; there is no separate validation
      step to race). §9 pins the detach-between-check-and-store case
      (impossible under CAS), the old-disconnect-after-new-connect case
      (the stale disconnect's write fails the generation CAS), AND the
      equal-generation overwrite case from AGY r25 (the C1-disconnect /
      C2-connect same-g collision — impossible under rules (i)-(ii) and
      pinned as a regression test).
      (iii) **Journal replay** (messages move into a generation-blind
      queue whose sender later picks whatever connection is active,
      sync_conn_write.go:135/268): the per-(sender,key) monotonic
      install generation (#2170) orders session state for the TRACKED
      class — upserts are refused when older than the stored
      generation INCLUDING tombstones (installGenGuardV4,
      sync_conn_gen.go:205), and deletes draw fresh strictly-greater
      generations with stale deletes refused and valid deletes recorded
      as tombstones (takeDeleteGenV4/deleteGenGuardV4,
      sync_conn_gen.go:179-322) — so a stale replayed upsert cannot
      overwrite a newer delete and a stale replayed delete cannot
      overwrite a newer install, for the tracked class. But #2170 does
      NOT universally order replay (Codex r23 blocker 2, with pinned
      code evidence): the generation maps are capped at 200,000 keys
      and a new key at capacity is deliberately NOT recorded
      (sync_conn_gen.go:23/45); a sender with no recorded stamp emits
      generation-0 deletes (takeDeleteGenV4/V6 → 0,
      sync_conn_gen.go:176) that can be journaled and replayed
      (sync_conn_write.go:69); a generation-0 delete is UNCONDITIONAL
      at the receiver and removes the stored tombstone
      (sync_conn_gen.go:263, pinned by sync_gen_guard_test.go:128 even
      against a generation-bearing live entry); a receiver map at
      capacity records no high-water generation for a new replacement
      (sync_conn_gen.go:233, sync_gen_guard_test.go:635), so an older
      nonzero replay sees no stored generation and applies; and once a
      zero-generation delete clears a tombstone, a delayed older
      install can RESURRECT the closed session — the exact reorder
      #2221's tombstone exists to prevent (sync_gen_guard_test.go:830).
      The disposition is therefore three-layered:
      (a) **epoch-ENVELOPE SEND guard — content-origin stamping at
      ENQUEUE, with the epoch advancing only where an authoritative
      prime is scheduled** (Codex r25 blocker 2: binding at DEQUEUE is
      too late — deltas A and B enter `sendCh` under epoch N; A is
      dequeued and waits while the connection aborts; epoch N+1
      connects and A is correctly discarded; but B is only NOW
      dequeued, so a dequeue-time guard binds it to N+1 EVEN THOUGH
      ITS CONTENT PREDATES THE ABORT — and a generation-zero B travels
      on the replacement connection and unconditionally deletes newer
      state. And the claimed cold-prime backstop is NOT universal:
      cold-prime arms only on a both-slots-empty transition
      (sync_conn.go:235/278), while routine single-fabric flips
      explicitly do NOT re-bulk (sync_conn.go:178/208), so advancing
      the compared epoch on such a flip would discard valid deltas
      with NO authoritative replay; and even where cold-prime occurs,
      `flushDeleteJournal` merely enqueues (sync_conn_write.go:135)
      while bulk sessions write directly under per-frame `writeMu`
      (sync_bulk.go:95), so the bulk is not necessarily ordered after
      the queued deltas). The rule is therefore two-part:
      (a1) **every `sendCh` entry carries an epoch ENVELOPE captured
      at the CONTENT-VERSION POINT, not at enqueue** — a FIRST-OFFER
      delta (upsert or delete, or direct raw-byte entry) is
      stamped with the connection epoch current AT THE MOMENT its
      per-key generation is drawn (`stampInstallGenV4/V6` /
      `takeDeleteGenV4/V6`, sync_conn_write.go:56/63/77/87), and the
      generation and the epoch travel together as ONE content-version
      tuple (Codex r27 blocker 1's first counterexample:
      `QueueSessionV4` stamps and encodes BEFORE calling
      `queueMessage`, so an abort landing between stamp and enqueue
      would hand PRE-abort content the NEW epoch at enqueue if the
      stamp point were the enqueue — capturing the epoch at the
      generation stamp closes that window by construction). A
      JOURNAL-REPLAYED delete is the deliberate exception: its
      generation was drawn at journal time and already binds its
      content version, so the replay RE-ENVELOPES at replay-enqueue
      under the current epoch (`flushDeleteJournal`,
      sync_conn_write.go:135) — the replay is a designed re-offer of
      pre-abort content the peer still needs (refusing it would
      strand peer state the journal exists to convey), and its
      journaled generation still orders it against same-key installs
      at the receiver (a stale replayed delete is refused by a newer
      live entry; the gen-0 subset remains the documented unordered
      class, bounded by the next authoritative bulk — layer (b)
      below); the
      sendLoop discards any envelope whose epoch is older than the
      connection it would send on, so a
      delta queued BEFORE an abort can never travel on a replacement
      connection regardless of when it is dequeued (the
      queued-behind-A case dies by construction); and
      (a2) **the compared epoch advances ONLY on transitions that
      schedule an authoritative prime** — an abort/teardown always
      primes (the fenced recovery drives cold-prime), while a routine
      no-prime single-fabric flip does NOT advance the guard's epoch,
      so valid deltas keep traveling on flips where the delta stream
      itself is the authority and nothing else will re-convey them;
      whenever the epoch does advance and deltas are discarded, the
      scheduled prime is the guaranteed backstop that re-conveys every
      still-valid session. The prime's ORDER is provided by an EPOCH
      BARRIER, NOT by routing bulk frames through the delta queue
      (Codex r26 blocker 2: the existing `sendCh` is explicitly
      NON-BLOCKING and LOSSY when full, sync_conn_write.go:36, and the
      bulk intentionally bypasses it through LOSSLESS DIRECT WRITES
      because an incomplete snapshot followed by `BulkEnd` would delete
      live peer sessions, sync_bulk.go:17/50 — so routing bulk frames
      through the lossy envelope path could drop frames and still
      deliver `BulkEnd`, which is catastrophic: the receiver reconciles
      immediately upon `BulkEnd`, sync_conn_read.go:205, and would
      delete the live sessions the dropped frames represented). The
      bulk therefore KEEPS its lossless direct-write discipline
      (writeMu sequence, sync_bulk.go:95), and the epoch barrier
      serializes it against the delta path: when a prime begins, the
      barrier (i) stops accepting NEW delta envelopes under the old
      epoch (the compared epoch advances first, so a delta stamped
      after the advance carries the NEW epoch in its content-version
      tuple — and such a new-epoch delta is safe in either send order
      relative to the bulk frames: its content version post-dates the
      abort just as the prime's snapshot does, and the receiver's
      per-key #2170 generation guard is the adjudicator of any
      overlap), (ii) waits for the delta queue to
      DRAIN to the barrier point (every old-epoch envelope either sent
      on the dying connection or discarded by the envelope rule), then
      (iii) the bulk writes losslessly under the new epoch, with
      `BulkEnd` committed ONLY after every bulk frame is confirmed
      written in the same direct-write sequence.
      The bulk's own frames obey CONTENT-VERSION BINDING rooted in a
      PRODUCER-ORDERING INVARIANT, not write-time stamping and not a
      Go-side lock around the mirror read (Codex r27 blocker 1's
      second counterexample: the batch iterator copies up to 256
      values before their callbacks run, maps_session.go:237, and
      today the bulk callback draws a FRESH generation at write time
      so a stale copy gets stamped above the change that overtook it;
      Codex r28 blocker 1's deeper cut: the "LIVE sessions map" is the
      asynchronously maintained BPF MIRROR, not the Rust helper's
      authoritative session table — Rust publishes the close event at
      session_delta.rs:282 BEFORE deleting the mirror row at
      session_delta.rs:406, so Go can consume the close, draw the
      tombstone `G1`, and REMOVE the recorded generation
      (takeDeleteGenV4, sync_conn_gen.go:179) while the mirror still
      shows `K=V_old` — no Go lock around the mirror read can order
      that, because the event stream and the mirror are two
      unsynchronized producer channels). The root rule is therefore
      PRODUCER-SIDE: **for a session Close, the mirror row for THAT
      INCARNATION is gone BEFORE the close is published on ANY
      outbound channel** (event stream, RPC fallback, recent-deltas
      ring), giving the load-bearing invariant: mirror-PRESENCE of K
      at a Go read implies NO close for K's current incarnation has
      been published, hence none consumed, hence Go's generation map
      still holds K's install record (or never had one) — the mirror
      re-read IS a consistent cut relative to Go's generation state.
      Two refinements make the rule true rather than aspirational
      (Codex r29 finding 1, AGY r30 findings 1-3, Codex r31
      finding 1):
      (R1) **a close is INCARNATION-GATED END-TO-END, with the gate
      atomic against same-key publish** — every close-side action
      first checks the closing session's expected incarnation (the
      #5213 stable session id from the producer's OWN authoritative
      record — the SessionTable entry for expiry/teardown; the
      shared_sessions entry for the tunnel-remap purge, which today
      hardcodes `session_id: 0` on its close deltas,
      tunnel_purge.rs:69, and must carry the entry's id instead;
      terminal teardown likewise supplies the id rather than
      hardcoding zero, session/install.rs:495) against the mirror
      row's stored id, under a STRIPED PER-KEY PRODUCER MUTEX that
      covers BOTH the mirror publish path and the compare-and-delete
      for that key (the mirror is a plain hash map, xpf_maps.h:96;
      publish uses `BPF_ANY`, publish_conntrack.rs:141; delete takes
      only a key, bpf_map/mod.rs:321 — an unserialized
      lookup→compare→delete is TOCTOU and a migrated publish would
      still be removed; publishes happen at session create/delete,
      not per packet, so the stripe is uncontended except for the
      exact race it exists to serialize). The verdict drives the
      WHOLE close, not just the delete: when the observed incarnation
      is NEWER (a same-key replacement already owns the key), the
      stale close is SUPPRESSED ENTIRELY — no mirror delete, NO
      PUBLICATION, no generation draw (Codex r31 finding 1's fatal
      inverse: close frames carry no session id,
      event_stream/mod.rs:662, and a published stale close draws
      `G_del > G_new` at the sender and tombstones the LIVE
      replacement at the peer, with the sender tombstone then
      suppressing that replacement from bulk recovery; the old
      session needs no tombstone of its own — the replacement's Open
      already supersedes its row at the strictly greater
      generation); when the observed incarnation matches (or the row
      is absent), the delete proceeds and the close publishes with
      the tracked tombstone generation. A delete syscall
      error is ENOENT-tolerant with bounded retry — after retries the
      close is still published (the tombstone is the peer's
      correctness channel) but the failure is counted and latches
      out-of-sync with the #2442 full re-export recovery, because a
      persistently unwritable mirror is dataplane-fatal, not a
      per-session condition — AND the sender records the omission in
      a SEPARATELY BOUNDED failed-delete omission index (4096, keyed
      set, consulted by the bulk callback so a surviving dirty row
      is OMITTED from every bulk instead of re-minted into a
      peer-side zombie — the sender-side delete tombstone from
      v15.18, now scoped to failed deletes; at omission-index
      OVERFLOW the recovery stops trusting the mirror entirely and
      the owed authoritative prime runs as the TABLE-TRUTH export
      (ExportOwnerRGSessions — the authoritative table never
      contains the closed K, so no capacity-bound zombie is
      possible, Codex r31 finding 2)); a replacement install stamps
      strictly-greater and clears the omission entry.
      (R2) **the funnel is EVERY outbound close producer in the
      userspace runtime — FOUR producers** — the per-session
      expiry/teardown path (session_delta.rs), the terminal-teardown
      path (session_glue/mod.rs:546), the daemon's policy-
      invalidation path (QueueDeleteV4/V6 even when the mirror
      deletion returned an error, daemon_policy_invalidate.go:357 →
      session_store.go:391), AND the tunnel-remap purge
      (`purge_remapped_tunnel_sessions`, tunnel_purge.rs:47-103,
      which constructs forward Close deltas and pushes them via
      `push_purge_close_deltas`/`push_delta_lossless` while removing
      the shared_sessions entries — AGY r30 finding 1) all obey the
      same incarnation-gated discipline: each supplies the closing
      session's expected id from its authoritative record (the purge
      carries the shared_sessions entry's #5213 id instead of the
      hardcoded `session_id: 0` its close deltas use today,
      tunnel_purge.rs:69; and its removal path uses the REAL
      conntrack FDs — today the default removal runs with FDs `-1`,
      session_import.rs:288 → bpf_map/mod.rs:685, so the mirror
      invariant could not apply, Codex r31 finding 1), so no
      producer can publish a close whose incarnation is stale. The
      claim is scoped (Codex r31 finding 9): the kernel conntrack GC
      sweep (gc.go:288/335 → QueueDeleteV4/V6 callbacks,
      daemon_run.go:248) is a fifth producer ONLY in the legacy
      dataplane — userspace mode disables that sweep entirely
      (daemon_run.go:230); if it ever runs it obeys the same
      universal producer generation discipline.
      The purge/GC helper-local delete path additionally DRAWS a
      sender-side generation for every tracked key instead of
      emitting an unconditional generation-zero delete (today
      `delete_synced_session` forces gen-0, session_import.rs:245 —
      helper-local deletes are authoritative, but a gen-0 delete
      applies unconditionally and can kill a newer same-key
      replacement imported after it, Codex r30 finding 1; under the
      universal producer rule the purge's outbound deletes take the
      tombstone generation, and gen-0 remains ONLY for genuinely
      untracked keys in the documented unordered class, bounded by
      the next authoritative bulk).
      The invariant is scoped to OUTBOUND-published closes of
      locally-originated sessions: the other mirror-removal paths
      (session_glue/mod.rs:437/577/926 — worker-synced redirect and
      import-path removals) are receiver-side or redirect-lifecycle
      machinery that never outbound-publishes a delete for a
      locally-owned key (a sync-imported session's delete is SENT by
      the peer through ITS ordered funnel and consumed here via the
      receiver import path), and the bulk's owned-zone filter
      (ShouldSyncZone + IsReverse, sync_bulk.go:94-96) scopes the
      snapshot to rows this node answers for.
      The reverse direction gets a RECEIVER-side rule, not a
      producer invariant (Codex r29 finding 2: an Open published
      while its mirror write failed — publish_conntrack.rs:141 logs
      the failure without suppressing the Open — and consumed
      immediately before BulkStart lands in the gap: the receiver
      installs K, BulkStart REPLACES the received sets,
      sync_conn_read.go:183, the mirror-absent bulk omits K, and the
      BulkEnd reconcile deletes K solely for absence,
      session_store.go:627 — with no generation guard). The rule is
      RECEIVED-SET CARRY-FORWARD: at BulkStart the receiver seeds the
      new received set with every key installed by a delta SINCE the
      last completed bulk's BulkEnd (those installs were
      sender-stamped before the sender's BulkStart, so a complete
      snapshot re-records them anyway; carry-forward only rescues
      keys the snapshot cannot contain — and a key legitimately
      closed sender-side in that window is deleted by its
      strictly-greater tombstone through the normal delete path, so
      carry-forward cannot resurrect it). The carry-forward
      accumulator is RETAINED ACROSS ABORTED BULK ATTEMPTS and
      cleared ONLY at a completed BulkEnd (AGY r30 finding 4: seeding
      consumes it into bulkRecv at BulkStart; if that bulk aborts,
      the seed must still be present for the NEXT BulkStart — the
      accumulator clears on completion, not on consumption, so a
      BulkEnd1 → delta D1 → BulkStart2 → abort → BulkStart3 →
      BulkEnd3 trace keeps D1 carried and reconcile never deletes a
      live delta-installed session), and it carries a numeric cap
      (same 200k-key order as the generation maps). Overflow recovery
      runs INBOUND, not outbound (Codex r31 finding 3: the
      carry-forward set is RECEIVER-side peer state, and the v15.18
      `forceResync` arm drives THIS node's OUTBOUND `doBulkSync`,
      sync_conn_sweep.go:111, whose ownership filter excludes
      peer-owned rows, sync_bulk.go:95 — the sender-side boolean
      cannot reproduce a lost inbound D1): on carry-forward overflow
      the receiver forces a FENCED RECONNECT of the sync connection
      (the reconnect cold-primes the peer→us direction — the peer's
      needColdPrime fires on the fresh connect — producing the
      authoritative INBOUND bulk), with a RECONCILIATION HOLD on the
      overflowed episode: until that re-prime's BulkEnd completes,
      the receiver does not reconcile-delete any carried key (the
      hold prevents the absence-only delete of a key whose carry set
      overflowed); the same fenced-re-prime + hold is the bounded
      liveness contract for the incremental-index deferral (Codex
      r31 finding 8: deferred alias entries join the quarantine's
      payload-cap accounting, and overflow of THAT takes the same
      fenced-re-prime path — a deferred entry is resolved by the
      re-prime's definitive BulkEnd, never left uninstalled
      indefinitely). A persistent mirror-write
      failure on Open is additionally counted and latches out-of-sync
      with the #2442 full re-export, same as (R1). On top of that invariant the bulk callback, in ONE
      critical section per frame (the universal producer rule below):
      (V1) re-reads the mirror for K and encodes from the live value,
      never from the batch copy; (V2) uses the generation RECORDED
      for K when the live value equals the copy under the VERSIONED
      EQUALITY PROJECTION — an EXCLUDE-LIST, not an include-list
      (Codex r29 finding 11): every SessionValue field is
      version-relevant (flags, zones, reverse key, application
      timeout, ALG/log fields, FIB/tunnel data — types.go:15, all
      consumed at helper import, manager_ha.go:1595) EXCEPT the
      enumerated mirror-only restamps Rust performs without a
      generation draw (`last_seen`, re-resolved `policy_id`, and the
      packet/byte counters, bpf_map/mod.rs:364/438) — only those are
      excluded from versioned equality (Codex r28 minor 7), and mints-and-records a FRESH
      generation when the projection differs (current content has no
      reliable recorded version — minting for current content is
      exactly what `QueueSessionV4` does at stamp time, and
      over-minting the CURRENT content is always safe: the receiver's
      guard prefers the higher generation and the mint IS the
      sender's latest knowledge); (V3) OMITS the frame when the
      mirror lacks K — under the producer invariant that means the
      close was already published (or K never existed): the close's
      tombstone delta (durable via the delete journal,
      sync_conn_write.go:69) and the BulkEnd reconcile (K absent from
      the received set) converge the receiver; and (V4) KNOWN-STALE
      OMISSION with a sender-side trigger (Codex r28 major 6: a
      tombstone-refused frame at the receiver only bumps a counter,
      sync_conn_gen.go:435, and no refusal feedback reaches the
      sender — so the guarantee is sender-local): if, inside the same
      critical section, K's recorded generation has ADVANCED PAST the
      bound one (or the record was removed by a consumed close) since
      the live re-read, the frame is known-stale and is NOT written;
      re-conveyance is guaranteed by the advancing event's own
      durable channel — deletes ride the delete journal (journaled on
      any queue failure), installs arm `syncBackfillNeeded` on
      queue-full — and the arm RESETS/WAKES the sweep timer so the
      re-send fires immediately rather than waiting out the sweep's
      exponential backoff (today the flag does not wake the timer,
      which backs off to ten seconds, sync_conn_sweep.go:11/46 —
      Codex r29 finding 10; with the wake, the re-send bound is the
      sweep cycle, not the backoff ceiling) —
      no receiver feedback is required (documented residual: if
      the advancing event is a replacement whose delta is dropped by
      a full queue AND the bulk's BulkEnd lands before the woken
      sweep re-sends, the receiver deletes K at reconcile and
      re-installs it at the sweep — a bounded standby gap for a
      session that changed mid-bulk, identical in shape to today's
      in-flight-change-during-bulk behavior). Every
      wire interleave of bulk frames against deltas then resolves
      through the receiver's per-key #2170 guard with NO stale
      survivorship: a stale copy can never carry a generation greater
      than the change that overtook it. The cap-saturation residual
      (a generation-zero first-sight install racing a tombstone,
      bounded maps at 200k keys, sync_conn_gen.go:23/45) stays in the
      documented unordered class — the resurrected row is a DEAD
      session (tuple reuse re-conveys a fresh install that out-orders
      it), and the sender-cap arm drives a correcting authoritative
      bulk within one cooldown window whose discharge is now
      guaranteed by the debt machinery below.
      And the UNIVERSAL PRODUCER RULE (Codex r28 major 5): for EVERY
      producer — `QueueSessionV4/V6`, `QueueDeleteV4/V6`, the sweep
      first-offer path (which stamps and queues directly,
      sync_conn_sweep.go:142), and the bulk callback — the
      (generation draw, epoch capture, generation-map record) triple
      is ONE critical section (today `stampInstallGenV4` draws
      `nextInstallGen` and mutates the value BEFORE taking
      `genSentMu`, sync_conn_gen.go:119, while `putGenBounded`
      overwrites unconditionally, :45 — a draw-record split that lets
      a first-offer `G1` overwrite the bulk's newer recorded `G2`;
      moving the draw inside the record lock closes it). The journal
      re-envelope is explicitly NOT a producer under this rule
      (Codex r29 finding 9: it re-envelopes the epoch ONLY and
      PRESERVES the journaled generation, per layer (a1) — re-drawing
      at replay could make an old delete outrank a replacement); and
      every `sendCh` insertion path — including the barrier request
      path (`writeBarrierMessage`, sync_bulk.go:305) — carries the
      epoch envelope.
      Backpressure: if the
      delta queue does not drain within the barrier bound, the prime
      ABORTS BEFORE STARTING (it does not interleave with stale
      deltas) and is retried by the recovery machinery — and the
      retry is AUTHORITATIVE-ONLY (Codex r27 blocker 2: the current
      retry entry point `bulkSyncViaEventStreamOrFallback`,
      daemon_ha_sync.go:269/289, prefers the userspace event-stream
      exporter, legacy_dataplane.go:611, whose export is
      point-in-time Open deltas with NO BulkStart/BulkEnd and NO
      absence reconciliation, export.rs:85/143, forwarded through the
      LOSSY queueMessage path, sync_conn_write.go:36 — so a delete
      discarded by the epoch guard can stay absent from every such
      retry and the peer's stale row is never reconciled, while the
      readiness timeout releases the hold with the authoritative
      obligation unmet). A barrier-aborted prime therefore persists
      an authoritative-prime-owed state and the recovery re-drives
      ONLY the lossless direct-write `doBulkSync` (the #5085
      cold-prime window) or forces a fenced reconnect whose
      cold-prime IS `doBulkSync` — NEVER the event-stream exporter;
      a barrier abort does NOT consume the episode latch (one
      authoritative re-drive per cooldown window); and the owed state
      is a DAEMON-LIFETIME DEBT with a monotonic generation, not a
      SessionSync-local boolean (Codex r28 blocker 2: the existing
      latches are SessionSync-local, sync.go:448/500, and teardown
      destroys that object, daemon_ha_sync.go:1405, while the retry
      exits on replacement, :223 — and a plain boolean lets an older
      asynchronous success clear a newer abort's re-armed debt, the
      exact race the `needColdPrime` comment admits at sync.go:513).
      The debt (`authoritativePrimeDebt`) lives in the Daemon: ARMING
      (a barrier abort, or any transition that schedules an
      authoritative prime) increments a monotonic `debtGen` and
      records owed=true under the daemon's lifecycle lock; a
      REPLACEMENT SessionSync INHERITS the debt at construction — its
      first connection schedules the authoritative prime whenever the
      daemon holds owed=true, regardless of the wasDisconnected
      shape; DISCHARGE is EXACT-GENERATION COMPARE-AND-CLEAR on
      BulkEnd-ACK, not on write completion (doBulkSync success means
      BulkEnd was WRITTEN, sync_bulk.go:183 — the ACK arrives later,
      sync_conn_read.go:249): the ack-received path clears owed only
      when the acked prime's debt generation EQUALS the current
      `debtGen`, so an older async completion can never clear a newer
      abort's debt. The attribution state is explicit (Codex r29
      finding 6): at prime dispatch the sender records the
      (bulk epoch → debtGen) pair — outstanding primes are bounded by
      the episode latch, so a single current pair plus the rule "an
      ACK naming a non-current pair is ignored for debt purposes"
      suffices (today the ACK carries only the bulk epoch,
      sync_bulk.go:285, the sender retains one scalar pending epoch,
      :169, and the ack path is a no-argument async callback,
      sync_conn_read.go:249 — the callback gains the acked epoch as
      its argument and the pair map lives beside pendingBulkAckEpoch);
      and the debt has a TERMINAL clear: a chassis-cluster-disable /
      comms-teardown with NO replacement (stopClusterComms,
      daemon_ha_sync.go:1380) clears owed outright — the peer is
      decommissioned and there is nothing left to owe — so the debt
      cannot leak armed indefinitely through a disable. And the
      readiness timeout releases the VRRP HOLD but NEVER clears the
      debt (the hold release is the bounded degraded path; the debt
      still discharges at the next authoritative prime). The replacement also attaches its runtime
      BEFORE accepting connections (today the accept runs at
      daemon_ha_sync.go:1138 while `SetRuntime` lands at :1165, so an
      immediate cold-prime fails `sessions == nil`,
      sync_bulk.go:57 — under the debt rule a cold-prime attempted
      with no runtime attached DEFERS and re-arms instead of
      failing); the readiness-timeout degraded release remains the
      bounded last resort, and the barrier
      drain bound is a concrete implementation parameter — default
      2-5s, named alongside the other parameters in the summary below
      — AGY r27 nit 1). The guarantee
      is exact: `BulkEnd` can NEVER be emitted after any dropped or
      stale bulk frame — any bulk frame write failure aborts the bulk
      BEFORE `BulkEnd` (never emitted), and the receiver's
      incomplete-bulk rules (receive deadline, no ACK, fail-closed
      quarantine drop) apply.
      The journal envelope guard from the earlier layer is subsumed by
      this rule (the binding point moved from the dequeue/send effect
      BACK to enqueue-time content-origin stamping, covering all four
      flow shapes uniformly — Codex r26 nit 4).
      (b) **zero-generation / cap-saturated replay is the UNORDERED
      class**: a message whose per-key generation is 0 (sender untracked
      or receiver cap-saturated) carries no ordering information; its
      potential reorder damage (resurrecting a closed session, or a
      late zero delete killing a newer replacement) is bounded by the
      NEXT COMPLETE authoritative bulk reconcile — the sync protocol's
      convergence backstop for every provisional effect — and by
      (c) below;
      (c) **sender-cap saturation triggers a fresh authoritative bulk
      drive — with an EPISODE LATCH and an anti-self-rearm rule**
      (Codex r24 major 3: at capacity `putGenBounded` refuses EVERY
      unseen key on EVERY attempt, and `BulkSync` itself calls
      `stampInstallGenV4/V6` for every session (sync_bulk.go:95/135),
      so a refusal-armed bulk re-arms its own successor; with the
      active one-second sweep cadence (sync_conn_sweep.go:47/118),
      persistent saturation could produce back-to-back 200k-session
      bulks indefinitely — "one bulk per trigger edge" is insufficient
      because each bulk creates a new edge). The rule: (i) the
      saturation trigger COALESCES on a single dirty/pending flag and
      respects a minimum inter-bulk COOLDOWN (AGY r24 minor 2); (ii)
      an EPISODE LATCH sets on the FIRST refusal in a cooldown window
      and permits at most one recovery bulk per window; and (iii)
      refusals caused by `stampInstallGenV4/V6` DURING an active
      recovery bulk are recorded but CANNOT arm the next episode until
      the cooldown expires AND a new non-bulk-triggered refusal occurs —
      a recovery bulk never re-arms itself. The
      bulk is authoritative and needs no per-key ordering for its
      installs — saturation degrades to a bulk-driven sync cadence
      bounded by the latch, not an unordered delta stream.
      The pre-existing generation-0 tombstone-clearing residual
      (resurrection / killing a generation-bearing entry) is a
      #2221-family behavior pinned by today's tests
      (sync_gen_guard_test.go:128/635/830) and is OUT OF SCOPE for this
      issue — the abort-envelope guard in (a) prevents the
      ABORT-SPECIFIC instance of it; closing the general window (e.g.,
      not clearing a tombstone on gen-0 when the live entry carries a
      nonzero generation) is a named follow-up, not this plan.
      §9's journal race tests enumerate: sender-cap saturation triggers
      the bulk drive; receiver-cap replacement with no recorded
      high-water; a zero-generation delete clearing a tombstone
      (documented #2221 behavior, unchanged); an older install
      resurrecting after a gen-0 delete (bounded by the next
      authoritative reconcile); and the abort-envelope discard (an
      envelope queued pre-abort is dropped at drain when its bound
      generation is stale).
      (iv) **Clock writes** (`sendClockSync`): idempotent clock
      exchange — a stale clock sync is harmless and self-corrects on
      the next tick.
      To keep the arbiter starve-free, network I/O and callback
      execution inside every intent happen on background goroutines
      (`go s.OnPeerConnected()`, `go s.doBulkSync()` — spawned by
      `handleNewConnection`'s intent wrappers, AGY r22 nit 1) — only slot
      stamping, intent enqueuing, and goroutine spawning happen inside
      the atomic unit (AGY r21 nit 2). §9 pins a blocked-I/O test, a
      large-bulk (10k-journal-entry) test, an abort-mid-BulkSync test
      (partial bulk: no ACK, no reconcile, provisional installs converge
      at the next complete bulk), a BulkEnd-race test, and
      callback/journal generation-race tests proving AbortFenceTimeout
      and the atomic unit stay bounded under all of them.
      (5) **Reset-once ownership + deterministic detach**: when both
      slots confirm detached (or the named AbortFenceTimeout fires — a
      wedged handler's frames are commit-discarded per (4), so the
      reset is safe on timeout), the bulk / quarantine / capability
      STATE RESET runs EXACTLY ONCE, inside the serialized loop, owned
      by the fence transition — never per-callback — AND the transition
      GENERATION-INVALIDATES AND LOGICALLY DETACHES BOTH SLOTS before
      the fence releases, even on timeout (Codex r20 blocker 1a: today
      slots clear only from `handleDisconnect`, sync_conn.go:480, and
      the empty→connected edge that arms `needColdPrime` requires BOTH
      slots nil, sync_conn.go:248/278 — so a wedged slot left
      registered at timeout would let the next connection join a
      NONEMPTY registry, observe `wasDisconnected == false`, and MISS
      the fresh cold-prime clause (6) promises). Late callbacks from
      the detached slots are treated as stale (their slot generation is
      older than the reset's, so clause (4) discards their frames at
      commit). A second abort raised inside an active fence is a
      no-op when it carries no newer abort generation, or re-arms the
      fence at the higher generation with the same reset-once
      semantics.
      (6) **Peer convergence**: the fence clears and the
      abort-triggered per-peer backoff applies (unrelated disconnects
      are never delayed). The peer's reconnect attempts during the
      fence are REFUSED at (2); it retries and lands after cleanup on
      the genuine empty→connected cold-prime edge (sync_conn.go:139/
      :551, sync_bulk.go:65) with a FRESH bulk and a FRESH epoch —
      and the peer needs no fence awareness: the receiver-local fence
      enforces the transition regardless of peer version. Inbound
      frames from the aborted epoch are discarded by the TCP teardown
      (the discard-until-end alternative is rejected: session handlers
      use `bulkInProgress` only for bookkeeping and install trailing
      frames normally, sync_conn_read.go:109). This also covers the
      fourth epoch-death shape Codex named (single active-fabric reset
      after a prior successful bulk while the other fabric survives).
      Entries pinned to an aborted epoch are dropped fail-closed with
      the connection state (see the epoch-death rule below).
      §9 pins the race tests: install-between-detachments refused at
      (2); pending-frame-before-install discarded at (3); a stalled
      handler's post-reset frame discarded at (4); wedged-handler
      AbortFenceTimeout reset at (5); nested abort re-arm at (5);
      blocked-I/O boundedness at (2b); large-bulk (10k-entry)
      boundedness at (2b); abort-mid-BulkSync partial-bulk disposition
      (no ACK, no reconcile, provisional installs converge at the next
      complete bulk) at (2b/i); a BulkEnd race at (2b/i); callback
      generation-race cancellation at (2b/ii); journal generation-race
      (per-key #2170 ordering, not abort-generation) at (2b/iii);
      AbortFenceTimeout completing with a STILL-REGISTERED slot —
      the slot is generation-invalidated and logically detached anyway,
      so the next admission sees the both-nil registry and arms
      cold-prime (Codex r20 blocker 1a); and an abort raised BETWEEN an
      ADMITTED verdict and its setup tail — the atomic-admission rule
      (2b) makes that interleave impossible, asserted by a test that
      drives an abort between verdict and loop/callback/cold-prime
      (Codex r20 blocker 1b)
      (Codex r15 blocker 1 — deferred cross-epoch admission is unsafe:
      a frame quarantined in bulk E1 and admitted at wall-clock timeout
      would (a) race E1's BulkEnd reconcile, which deletes sessions
      absent from E1's received set — see the bookkeeping rule below —
      while the receiver ACKs the bulk and releases the sync-hold with
      the row still missing (sync_conn_read.go:240/244), and (b) be
      counted as part of a LATER bulk E2 if E2 starts first, falsely
      retaining a stale row whose delete was lost. Resolution is
      therefore EPOCH-DEFINITIVE: all quarantine actions run as events
      on the receiver's SERIALIZED event loop (a timer only enqueues a
      wakeup — the import path's generation-check/install/record
      sequence is safe only single-threaded, sync_conn_gen.go:381),
      and every quarantined entry RESOLVES AT THE EARLIEST OF:
      (i) ITS OWN BULK'S BulkEnd — at BulkEnd the complete snapshot is
      present, so the sibling-base check is definitive for that epoch —
      still-matching entries whose sibling base is in the received set
      CONFIRM-alias and drop; everything else is ADMITTED through the
      complete normal import path in the same serialized pass, BEFORE
      the bulk is ACKed and the sync-hold released;
      (ii) A SUPERSEDING BulkStart (Codex r16 blocker 2: fabric 0 can
      drop mid-E1 while fabric 1 survives — receiver bulk state resets
      only when ALL fabrics are down, sync_conn.go:496/554, the sender
      can re-drive a new bulk on the survivor, and E2's BulkStart
      UNCONDITIONALLY OVERWRITES E1's epoch and received maps,
      sync_conn_read.go:183/198 — so E1's pinned quarantines never
      receive their own BulkEnd). At a superseding BulkStart the PRIOR
      epoch's pinned entries are DROPPED fail-closed BEFORE the maps
      are overwritten — no cross-epoch leakage, and the superseding
      bulk re-sends every row anyway, so genuine rows re-quarantine and
      resolve on the completed retry (bounded delay, never a poison);
      (iii) A BULK DEADLINE / TEARDOWN (Codex r16 blocker 2: no receive
      deadline exists today — read timeouts merely send heartbeats,
      sync_conn_read.go:27, and the 30s VRRP timeout releases sync hold
      degraded without tearing down the bulk, manager.go:372 — so a
      per-bulk RECEIVE DEADLINE is required new behavior: on deadline
      the incomplete bulk aborts WITHOUT ACK, per the overflow-abort
      rule, and its pinned entries drop fail-closed per (ii)).
      Entries received OUTSIDE any bulk
      (incremental deltas) resolve on a 5s fallback timer instead —
      incremental frames carry no reconcile semantics, so the
      confirm-vs-admit DISPOSITION (quarantine release into the
      normal import path) applies with the CURRENT store — but the
      timer resolves ONLY the disposition and NEVER clears LINEAGE
      (Codex r38 major 3: "no sibling base present" at the timeout
      is not a genuine verdict — a lost-base alias copies the base
      exactly, daemon_ha_userspace_convert.go:399; the admitted row
      KEEPS its `alias-suspect` mark UNRESOLVED per §4.0.1 rule 7,
      and only the COMPLETE-PRIME definitive pass or the row's own
      close can clear it). No frame ever defers past its own bulk epoch).
      **Bulk bookkeeping is NOT gated**
      (AGY r15 blocker 1: a quarantined key is STILL RECORDED in
      `s.bulkRecvV4/V6` at decode time — it was genuinely received in
      the bulk — because `reconcileStaleSessions` /
      `ReconcileClusterBulk` (sync.go:1086-1126) treats any live
      session whose key is absent from the received set as stale and
      DELETES it at BulkEnd; gating the bookkeeping would delete every
      genuine self-NAT / identity-NPTv6 session ~50 ms after the bulk
      completes, before any resolution could run. The
      quarantine gates ONLY the import (install / publish / reserve /
      companion synthesis), never the "was received" record).
      Confirmation is ORDER-AGNOSTIC (Codex
      r14 blocker 2: the sender queues canonical base FIRST and alias
      SECOND on open, daemon_ha_userspace_stream.go:370/375/384, so the
      base has normally ALREADY been imported when the alias arrives —
      confirmation checks a BOUNDED RECEIVER-SIDE BASE-IDENTITY INDEX
      for a sibling canonical base at quarantine INSERTION (a canonical
      row whose forward-wire form equals the quarantined key with an
      identical NatDecision and an equal NON-ZERO RTFlowSessionID —
      the r6-r8 predicate, reliable for an actual pair) and confirms
      immediately; only when NO sibling base is present (the
      lossy-reorder alias-first case) does the entry wait for the
      base's arrival or the timeout). The index — not the session
      store — is the predicate's source (Codex r28 blocker 4:
      `SessionSync.sessions` is a `dataplane.SessionStore`,
      sync.go:293, whose reads delegate to the BPF session map,
      session_store.go:118, and `RTFlowSessionID` is sync-only —
      absent from that ABI, types.go:114, lifted as zero,
      bpf_session_value.go:204 — so the store can NEVER satisfy the
      equal-nonzero predicate and the base-first normal case would
      fail open at BulkEnd, recreating the synthesized companion the
      quarantine exists to prevent). The index is populated at DECODE
      time — the same serialized point where bulk bookkeeping records
      the key (sync_conn_read.go:110 ordering), where the decoded
      frame's RTFlowSessionID IS present: every SNAT-flagged
      non-NAT64 canonical-candidate frame records (forward-wire
      relation → RTFlowSessionID); and the id is PRESERVED ACROSS HA
      HOPS (Codex r30 finding 6's first failure: a promoted legacy
      standby re-bulks its imported rows with the id lifted from the
      BPF store — where it is ZERO, bpf_session_value.go:75/204,
      encoded as zero by sync_bulk.go:95 — so the downstream receiver
      can never satisfy the equal-nonzero predicate and admits the
      alias): the receiver retains the received RTFlowSessionID in
      its SYNC-SIDE session record (the #5212 id is the ORIGINATING
      node's stable id by design — it must survive re-export), and
      every re-bulk/re-export encodes the id FROM that record, never
      from the zero-lifted BPF field. the index is scoped to the bulk
      epoch (dropped at BulkEnd after the quarantine resolution pass
      — the complete-snapshot resolution IS the definitive check) and
      to the incremental-delta fallback window (entries expire with
      the 5s timer). Its cardinality rule is NOT the quarantine cap
      (Codex r29 finding 5: the wire has no disposition, so every
      ordinary non-fabric SNAT base is indexed — pricing the index at
      the 4096 quarantine cap would let >4096 ordinary SNAT rows
      abort EVERY authoritative bulk and never ACK): the bulk-epoch
      index is bounded by the bulk's own received-set cardinality —
      the same order as the existing bulkRecv maps (sync.go:518),
      which already retain every received key — so index growth can
      never abort a bulk; ONLY the incremental-window index carries a
      numeric cap (4096), and ITS overflow DEFERS the excess
      alias-signature entries to the NEXT BULK's definitive BulkEnd
      resolution rather than timeout-admitting them (AGY r30 finding
      5: timeout-admission installs a real alias as a canonical row —
      the synthesized broken companion — so under a >4096 inter-bulk
      burst the excess would misdeliver return traffic; deferral
      keeps the alias row uninstalled — the base session flows
      normally, only the fabric-redirect affordance waits — and the
      next bulk's complete snapshot resolves definitively; the 5s
      timeout-admission remains ONLY for the genuine lost-base case,
      unchanged), never aborts anything.
      And confirmation PURGES (the r29 stale-row hole: a lost-base
      incremental alias timeout-admitted as a canonical row, then
      re-received in a later complete bulk — the alias key lands in
      bulkRecv before its frame confirms and drops, so reconcile
      keeps the admitted row, sync.go:1080): a confirm-alias verdict
      additionally issues the LOCAL delete for any previously
      admitted row at the quarantined key through the normal
      delete path, so a re-received alias can never leave a stale
      admitted companion behind. Two refinements make the purge
      total and safe (Codex r30 findings 2 and 6):
      (P1) a timeout-admitted alias row is PROVISIONAL — every
      completed BulkEnd re-evaluates it against the definitive
      snapshot (alias signature + sibling base present), purging it
      even when NO new alias frame ever arrives — the active derives
      explicit aliases only on the incremental path
      (daemon_ha_userspace_stream.go:370), so an admitted alias would
      otherwise be carried forward and retained by every reconcile
      indefinitely; and
      (P2) the purge is EXACT-PUBLICATION compare-and-delete — it
      deletes the admitted row ONLY when the stored row IS that
      admitted publication (session-id matched), never key-only
      (key-based UpdateAny/delete would delete a genuine direct
      replacement row D that legitimately took the key after the
      admission, maps_session.go:69 / session_store.go:537 — outside
      the documented shared_ops.rs:907 residual). The compare-and-
      delete's OWNERSHIP is settled by §4.0.2 (Codex r34 major 11):
      the purge executes INSIDE THE HELPER via rule 4's transaction
      with publication identity (the cross-writer atomic seam exists
      by construction under sole-writer), with the explicit
      publication exception — a receiver-local sync-imported alias
      purge NEVER emits a Close toward the canonical owner
      (delete_synced.rs:20's local-only shape).
      A confirmed entry is dropped and its key enters the
      delete-suppression set. On timeout the entry is ADMITTED as a
      canonical row by DISPATCHING THE STORED FRAME INTO THE COMPLETE
      NORMAL import path — generation checks, timestamp rebasing,
      coordinator reserve, and helper dispatch
      (`WorkerCommand::UpsertSynced`), identically to a non-quarantined
      frame reaching `installClusterSynced*` (sync_conn_read.go:110 →
      sync_conn_gen.go:435; AGY r14 nit 2 + Codex r14 minor 4) — PLUS a
      guarded bookkeeping touch: the key is added to the CURRENT bulk's
      received set ONLY IF a bulk is currently open (AGY r15 blocker 1:
      after BulkEnd the map is nil'd, sync.go:1090, so an unconditional
      write panics with assignment-to-nil-map; and a session admitted
      between bulks needs no bookkeeping at all — reconcile only runs
      at BulkEnd):
      this is the genuine self-NAT case, the identity-NPTv6
      fabric-redirect case (no alias is ever derived for it —
      daemon_ha_userspace_convert.go:511 returns false when wire == key),
      and the genuinely-lost-base alias case (which degrades to TODAY's
      behavior for that case — bounded, and only on a wire loss).
    - **Deletes**: suppressed only for keys in the
      confirmed-delete-suppression set, with the lifecycle matching the
      actual close ordering (Codex r14 blocker 2: the exporter queues
      the BASE delete BEFORE the alias delete in the same close delta,
      daemon_ha_userspace_stream.go:398/403 — so the suppression entry
      does NOT clear when the base's delete processes; it clears when
      the FIRST delete for the key AFTER the base's delete is consumed
      (the alias's own delete, which the suppression then swallows), or
      on a short bound if that delete was lost on the wire). Documented
      residual: a genuine DIRECT row sharing the key with a confirmed
      alias (the #2387 overlap corner) whose own delete arrives while
      suppression is active is suppressed and the row strands until its
      OWN session timeout (bounded — entries expire on their own
      timeouts) — versus TODAY, where the alias upsert clobbers that
      row at publish with certainty (shared_ops.rs:907). Every matrix
      cell is strictly safer-or-equal to today.
  - **Why dropping/omitting is safe (verified five times)**:
    the explicit alias row is REDUNDANT with the derived forward-wire
    index row the base session's own publish inserts
    (shared_ops.rs:943-957): exact shared lookup falls through to that
    derived index (shared_ops.rs:630); materialization carries the base
    canonical key (shared_ops.rs:549); RG-promote republish indexes the
    derived map (shared_ops.rs:432-437/:950); activation prewarm needs
    only the base rows; BPF publication emits canonical + forward-wire
    + reverse-wire + reverse-canonical keys for the base
    (bpf_map/mod.rs:76). No Rust forwarding consumer requires the
    explicit row.
  - **Side fix (a live shipped hazard, verified by Codex r11/r12 and AGY
    r11)**: the import path synthesizes a reverse companion for every
    forward import including alias rows
    (synthesized_synced_reverse_entry, shared_ops.rs:750 — no alias
    detection), and `NatDecision::reverse` sets `rewrite_dst` to the
    supplied original source (nat/mod.rs:106), so an alias entry yields
    a companion that un-NATs replies to the firewall's own address E
    instead of the client H. Base and alias companions derive the SAME
    reverse key K=(S→E) (session/key.rs:94); the alias's companion
    publishes SECOND (canonical-then-alias export order,
    daemon_ha_userspace_stream.go:370) and displaces the correct one in
    the last-write-wins shared reverse map every sweep — the churn the
    `record_shared_nat_displacement` exclusion documents
    (shared_ops.rs:92-120). Return packets consult the exact session key
    K (shared_ops.rs:602/630), so the poisoned companion is
    forwarding-relevant TODAY. Sender omission (new+new) and
    quarantine-confirmation (legacy) both prevent the poisoned
    companion from ever forming; `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS`
    goes quiet for fabric-redirect SNAT sessions.
  - **Mixed-version matrix** (no cell regresses): new+new: omission —
    zero alias traffic, zero collateral. old sender + new receiver:
    signature quarantine — genuine rows admitted after the window (a
    sync DELAY, not a drop, for the corner); aliases from an old
    sender are NOT confirmable (Codex r31 finding 7: confirmation
    requires equal NON-ZERO RTFlowSessionID, and the old sender's
    definitive bulk encodes the id from the zero-lifted BPF field —
    it never had the preservation machinery — so in the lost-base
    case neither the base nor the alias carries a matchable id and
    P1 cannot purge). The honest cell semantics: a provisional
    admitted alias in this cell expires with its SESSION's own
    lifetime (the alias mirrors a live fabric session; the row is
    bounded by that session's close/timeout — the documented
    residual, strictly better than today's CERTAIN broken companion
    at publish time), and full confirmation requires new+new.
    new sender + old receiver: no advertisement → sender
    keeps deriving; old receiver treats aliases as canonical — TODAY'S
    exact behavior (broken companion included — the status quo, not
    worse). old + old: status quo.
  - **Helper side**: no alias-specific OWNERSHIP handling — the
    ownership machinery (reserve/holders/tri-state/staged
    replacement) sees only canonical rows. (Codex r37 minor 3 +
    r38 major 4 — the lineage marks' AUTHORITATIVE carrier and its
    full path, reconciled with §6: the carrier is the additive
    `SyncedSessionEntry` extension — TWO additive fields now,
    `pub_token` AND the alias stage (§6 is updated accordingly) —
    because `SyncedSessionEntry` embeds `SessionMetadata`
    (worker/mod.rs:375) and the import moves `entry.metadata`
    into the table (upsert_synced.rs:64), so the stage set at the
    Go receiver's quarantine insertion rides the import request
    (the additive optional field on BOTH the JSON
    `SessionSyncRequest` and the binary codec, protocol_ha.go:33 /
    control.rs:1008 / session_sync.rs — per #1961; an old helper
    ignores it and the receiver treats its absence as legacy),
    lands in the table's metadata, and is preserved by worker
    replication and by the promotion Open path — with the
    promotion Open itself GATED on the stage (a suspect row's
    promotion Open is suppressed until the definitive verdict,
    session/mod.rs:1516 emits only for clear or unmarked rows).
    Every exporter is explicitly gated: promotion Open, owner-RG
    export, helper snapshot export, Go bulk, and Go sweep. §9
    pins suspect→promote suppression, genuine-clear/export,
    stage preservation, and the concurrent-export race.)
- **Neutral paths**: promote (promote.rs:99), demote (install.rs:568),
  #1752 in-place refresh — NO reserve/release calls.
- **Reverse-companion lag (documented inherited window, SMR r5 N16)**:
  forward and reverse companions of one flow can live in DIFFERENT
  workers' tables (internal and external tuples hash differently). The
  identity frees when the holder set empties (forward reap −{Worker} +
  canonical removal −{Shared}), while a reverse companion elsewhere is
  holder-neutral and lingers until its own reap or the delete-replication
  relay (`replicate_session_delete` — it ENQUEUES per-worker commands,
  session_glue/mod.rs:881, so the bound is queue/relay-or-expiry, not a
  strict millisecond deadline; the session_delta.rs:436-446 removal
  covers both keys) reaches it — a queue/relay-or-expiry-bounded window
  in which a re-minted identity's reply could land on the lingering
  reverse entry. This window exists TODAY for pool mode (pool port freed
  at forward reap while the reverse companion lingers; the #3011 recycle
  FIFO is only a reuse-delay, also churnable), so the change does not
  widen it; closing it belongs to the session-teardown domain, not this
  NAT-admission fix. The core invariant statement is scoped accordingly:
  continuous holding on every scope EXCEPT the relay-bounded
  reverse-companion edge, which matches shipped pool discipline.
- Net effect: the identity survives while ANY HOLDER-BEARING FORWARD
  replica or shared canonical row lives node-wide (reverse companions are
  holder-neutral by design — Codex r6 nit 5) — the #6522 hazard cannot
  exist in this registry.

### 5.7 Cross-domain overlap foreclosure with DRAIN (Codex r3 blockers 1-2, r4 blockers 2-3)

The interface registry, source-pool allocators, and NAT64 allocators are
DISJOINT occupancy domains; a source pool (or NAT64 pool) containing an
egress interface address reintroduces the collision across the seam.
Foreclosure at BOTH layers, plus a DRAIN discipline for already-live
sessions:

1. **Commit validator** (#5144 extension): interface-mode egress addresses
   join the owner set DEDUPED BY ADDRESS (multi-rule same-WAN configs must
   not false-reject). Overlap → REJECT at strict commit; WARN on tolerant
   load / peer-sync (#5837/#1960 no-brick doctrine). The owner set also
   gains WHOLE-ADDRESS STATIC mappings whose translated address coincides
   with an interface-SNAT egress (Codex r29 finding 4: static SNAT
   returns before interface/source admission, nat_exception.rs:57, and
   preserves the source port for whole-address mappings,
   static_nat.rs:746, so static `A:5555→S:80 → E:5555→S:80` and
   interface `H:5555→S:80 → E:5555→S:80` produce ONE wire identity that
   the 1:N map cannot disambiguate, key.rs:19/lookup.rs:222 — while the
   strict validator enumerates only source-pool and NAT64 owners,
   compiler_validate_strict_nat.go:2617, and the static/interface-address
   gate is warning-only and even SUPPRESSES the warning when interface
   SNAT owns E, compiler_validate_warn_nat_iface_addr.go:289 — the exact
   unsafe case). That suppression is narrowed so a whole-address
   port-preserving static on an interface-SNAT egress still warns under
   tolerant load and rejects under strict.
2. **Snapshot builder + DRAIN** (interface snapshots resolve LIVE kernel
   addresses, interfaces.go:455-465; DHCP triggers a full recompile on
   address change, daemon_dhcp.go:73/85):
   - **Egress-address derivation matrix** (Codex r4 major 8): per
     interface-mode rule, the overlap candidate set is — `to-interface`:
     that interface's addresses; `to-zone`: the zone's interfaces'
     addresses; `to-routing-instance`: the RI's interfaces' addresses;
     NO to-side scope (or from-side only): ALL dataplane interfaces'
     addresses (wildcard, matching the Rust `scope_matches` semantics at
     nat/source.rs:351 — the Go precedent that collected only non-empty
     `ToZone` and returned nothing for unscoped rules, maps_sync.go:1735,
     is insufficient and is replaced). §9's builder test matrix covers all
     four scope shapes.
   - Any pool address overlapping a derived candidate address marks that
     POOL unusable (`pool_failure`/`PoolUnusable` — fail-closed NEW pool
     admissions). NAT64: the overlapping rule is emitted with an EMPTY pool
     (shipped native fail-closed at nat64.rs:1123; the old NAT64 allocator
     is retained SEPARATELY from the active empty prefix — normal reuse
     requires a byte-identical pool, nat64.rs:937, Codex r4 verified).
   - The dataplane RETAINS the quarantined pool's previous allocator as a
     DRAINING domain (a compatibility carry-over key that ignores the new
     failure marker and survives repeated quarantined snapshots — Codex r4
     verified the current `allocator_key()` drops carry-over on
     `pool_failure`, source.rs:337/726, so the drain retention is an
     explicit new key); releases and mirrored reserves keep reaching it
     (§5.3 drain-vec scan); the per-index live counter (§5.3's
     authoritative `addr_index`) makes the drain O(1)-observable.
   - **Uniform mint quarantine** (Codex r5 blocker 3 — v5 quarantined
     only INTERFACE mints, so a re-enabled edited pool could mint an
     identity an older draining generation still owns): while ANY
     generation/domain holds live allocations on an address E, NEW mints
     on E are quarantined in EVERY domain — pool admission SKIPS
     quarantined addresses in its address loop (allocates on a
     non-quarantined pool address; exhaustion only if ALL are
     quarantined — and an address-persistent/sticky pool, whose loop is
     single-attempt by contract, yields `AllocatorExhausted` when its
     sticky address is quarantined: fail closed, NEVER rotate a sticky
     flow to a different address — SMR r6 nit 2; the same fail-closed
     posture applies to deterministic CGNAT (fixed address derived from
     the subscriber, allocator.rs:1482), persistent-NAT pinned-address
     reuse — BOTH the address-only persistent path (allocator.rs:1955)
     AND the port-translating persistent path that returns a pinned lease
     BEFORE the address loop (allocator.rs:1114, so the quarantine gate
     sits at the lease decision, not only in the loop — Codex r7 minor
     5), and deterministic NAT64 (allocator.rs:1561)), NAT64 likewise,
     interface-mode mints fail closed.
   - **Whole-address static occupancy accounting** (Codex r29 finding 4's
     runtime half): a whole-address (bijective, port-preserving) static
     mapping's flows register their translated occupancy —
     `(E_static, original_port, effective_dst)` — in the interface
     registry as a FIXED-ADDRESS holder, exactly like the other
     fixed-address modes above; a MAPPED-PORT static registers with
     the EMITTED external source port — the static decision's
     `rewrite_src_port` (Codex r31 finding 5: `MappedPort` is the
     INTERNAL post-DNAT port while `MatchDestinationPort` is the
     external wire port, protocol_nat.go:163, and return SNAT rewrites
     internal→external, static_nat.rs:746 — reserving the wrong field
     defends nothing; the shipped `8080→80` case,
     static_nat_mapped_port_2491_test.go:20, emits `E:8080` and MUST
     reserve `E:8080`, pinned in §9). Occupancy is
     acquired at EVERY static decision point — including the INBOUND
     static-DNAT path (selected pre-routing,
     poll_descriptor/mod.rs:1018, whose replies reuse the stored
     decision, session/lookup.rs:181, and never visit the reverse
     static-SNAT matcher, nat_exception.rs:57 — the inbound decision
     point is the only place inbound-created sessions can claim
     occupancy, §6 inventories it). The two collision directions resolve
     asymmetrically by design: a static flow whose occupancy is already
     held FAILS CLOSED (static cannot PAT without breaking bijectivity —
     same posture as sticky/deterministic modes — and the drop carries
     its OWN §5.8 counter, not the interface exhaustion counter); an
     interface-mode mint
     colliding with a static-held occupancy PATs (interface can).
     Provenance (Codex r30 finding 5): a static mapping's holder
     RELEASES on the mapping's config removal — through the SAME
     drain discipline, not an immediate free (Codex r31 finding 5:
     the config-refresh preserves live worker sessions,
     snapshot_refresh.rs:356 purges only tunnel remaps, so an
     established static session would keep emitting its tuple after
     the occupancy was handed to interface SNAT; the holder enters
     DRAINING on removal — live sessions keep their tuple until
     close, new interface mints on the address quarantine until the
     drain completes); static-held addresses
     join the uniform mint quarantine's domain enumeration (a static
     edited mid-drain releases its occupancy into the SAME drain
     discipline — releases keep reaching the draining holder); and
     pool/NAT64 enablement on a static-held address hits the strict
     validator's owner set before any runtime state forms.
     §9 pins both directions plus the commit-validator arm above.
     (`InterfaceOverlapDraining`) since their "pool" is the single
     address. Reserves (ownership claims for existing sessions) are never
     quarantined — they are tri-state per §5.3.
   - **Drain-marker ordering** (Codex r4 blocker 2): the drain marker for
     an address E is installed in the registry BEFORE the new RuntimeView
     is published to workers (before the worker-visible store at
     snapshot_refresh.rs:458/472 — early installation is safe, it can only
     over-quarantine; late installation is not). Under the OLD dataplane
     state the overlap does not yet exist (the pool edit / address
     addition is not applied), so mints before the marker are consistent
     with the old config; mints under the new state are quarantined from
     the first packet. The v4 "race window" is CLOSED, not documented.
   - **Atomic drain lift**: when the drain empties, the draining entry and
     its allocator are removed from the draining map under ONE registry
     lock, and the quarantine lifts in the same critical section — a late
     synced reserve after that point gets `NotThisDomain` from the
     (removed) pool domain and transfers to the interface registry
     (ownership continuity), never resurrects the drained allocator
     (Codex r4 blocker 2's closed/resurrection protocol). A re-ENABLED
     pool (marker removed by a later config) starts minting on its
     non-quarantined addresses immediately and on E only after every
     older generation for E drains (the uniform rule above).

### 5.8 Observability (additive, production)

SIX ADDITIVE optional counters on the existing helper status wire,
plumbed via the FULL #1760-W3' precedent (protocol/control.rs:343 +
coordinator/status.rs:241 + server/lifecycle.rs:228 init +
server/helpers/status.rs:102 refresh; protocol_status.go:287 +
pkg/api/metrics.go:377 + Describe registration at metrics.go:791 +
metrics_descriptors_userspace_session.go:27 + metrics_userspace.go:677;
additive per #1961), PLUS THREE GO-side Prometheus counters (the
§5.6 alias-discipline counters — no helper wire involvement). For
clarity (AGY r25 nit 3): the SIX helper-side counters are
`xpf_userspace_interface_snat_pat_collisions_total`,
`xpf_userspace_interface_snat_identity_exhaustion_total`,
`xpf_userspace_interface_snat_registry_cap_exhaustion_total`,
`xpf_userspace_interface_snat_sync_identity_conflict_drops_total`
(the last recorded inside the Rust helper coordinator,
ha/session_import.rs),
`xpf_userspace_static_nat_occupancy_conflict_drops_total` (the §5.7
static whole-address/mapped-port fail-closed drop — its OWN counter,
never folded into the interface exhaustion counter, AGY r30 finding 7),
and `xpf_userspace_ha_export_alias_lineage_skips_total` (the helper-side
export skip of EITHER lineage mark — `alias-suspect` while unresolved
or permanent `alias-lineage` — counted per export path, AGY r37 nit 1 /
r38 nit 1);
the THREE Go-side cluster counters are
`xpf_userspace_session_sync_forward_wire_alias_ignored_total`,
`xpf_userspace_session_sync_alias_quarantine_admitted_total`, and
`xpf_userspace_session_sync_alias_quarantine_overflow_total`
(pkg/cluster): 6 + 3 = 9 total:
- `xpf_userspace_interface_snat_pat_collisions_total` — identity-mint
  conflicts that took the PAT probe;
- `xpf_userspace_interface_snat_identity_exhaustion_total` — completed
  full-cycle probes (per-destination exhaustion) + port-less fail-closed
  collisions + drain-quarantine rejections;
- `xpf_userspace_interface_snat_registry_cap_exhaustion_total` — the
  per-address 64512 flow-registry cap AND the 256-retained-allocator cap
  (both "cannot create more registry state" events; Codex r4 minor 9 +
  nit 10 — the two §4.3 exhaustion modes are now counted distinctly). An
  optional `reason` label (`flow_cap` vs `allocator_cap`) is an
  implementation-time refinement, not a plan requirement (AGY r5 nit 1).
- `xpf_userspace_interface_snat_sync_identity_conflict_drops_total` —
  coordinator import-conflict drops (§5.6). Its doc text states that the
  series ALSO includes the BENIGN legacy-alias conflict drop from the
  legacy window (a fabric alias importing into its own base's identity —
  indistinguishable from a genuine conflict by construction, hence
  fail-closed there; on the negotiated-omission path aliases never
  conflict at all) — SMR r9 N17 — and that NON-ZERO counts are EXPECTED
  during a mixed-version rolling upgrade while receiving from legacy
  senders (AGY r14 nit 3).
- `xpf_userspace_session_sync_forward_wire_alias_ignored_total` —
  GO-side Prometheus counter for fabric forward-wire alias rows
  confirmed-dropped from the receiver-side quarantine (§5.6; a routine
  benign steady-state event for fabric-redirect sessions on the legacy
  window — operator-visible proof the discipline is active); and
  `xpf_userspace_session_sync_alias_quarantine_admitted_total` — GO-side
  counter for quarantine-timeout ADMISSIONS (genuine self-NAT /
  identity-NPTv6 / lost-base rows — Codex r14 nit 5: the collateral is
  its own series, not a note on the drop counter).
- `xpf_userspace_session_sync_alias_quarantine_overflow_total` — GO-side
  counter for quarantine-CAP saturations (each triggers a terminal bulk
  abort per §5.6's recovery contract; the operator-visible signal that
  the cap is undersized for the deployment — Codex r16 blocker 1,
  AGY r20 nit 1). The Rust-side
  `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS` going quiet for the same
  sessions confirms the companion-poisoning side fix.
`debug_log!` is feature-gated (afxdp/mod.rs:51) — test/dev aid only.
Exhaustion additionally rides the existing production NAT-failure event
path (`record_source_nat_failure`, nat_exception.rs:154). PAT'd sessions
are operator-visible through the already-generic session display. Registry
occupancy/holder introspection is a named follow-up, not this PR.

## 6. Public API preservation

Preserved byte-for-byte: `NatDecision`, `SourceNatLookup`, `SessionKey`,
the Go→helper snapshot
protocol (`SourceNATRuleSnapshot` and the NAT64 snapshot gain NO fields —
empty-pool is the NAT64 fail-closed channel), all CLI/gRPC surfaces.
NO wire change of any kind for the core fix; beyond it, the plan adds
ADDITIVE-ONLY, old-peer-ignorable wire elements per the #1961
precedent (Codex r34 finding 6's revision of the earlier absolute
statement): the ONE additive
`syncMsgCapability` frame on a dedicated ticker (advertised by new
receivers; new senders omit alias derivation when it is present — old
peers on both sides see today's exact behavior), the dual-lane
ordering tuple `(worker_id, source sequence, helper incarnation /
table epoch)` on both delta lanes (a peer not advertising the
capability disables the fallback lane entirely — the safe
degradation), the one-bit prime-REQUEST field, and the optional
mirror provenance bit (rule 7); every addition is explicitly NOT a
handshake field, since unkeyed deployments bypass the handshake,
sync_auth.go:321).
Additive-only wire-visible changes (#1961-safe): the six helper-side
§5.8 status counters (three more — the alias-discipline counters —
are GO-side Prometheus, §5.8).
`SyncedSessionEntry` gains TWO additive fields (AGY r39 nit):
`pub_token: u64` (the coordinator-local publication token of §5.6 —
stamped at publish inside the helper, HELPER-INTERNAL: it is NOT read
from or written to any Go-facing wire, and older in-image rows read as
token 0), and the alias lineage STAGE (`alias-suspect` /
`alias-lineage` / clear — the §5.6 lineage carrier, Codex r38 major 4:
unlike `pub_token` this field IS carried on the sync wire as an
additive-optional field per #1961, on both the JSON
`SessionSyncRequest` and the binary codec; an old peer/helper ignores
it and the receiver treats its absence as the legacy posture, never as
'clear').
The six helper-side §5.8 status counters are additive optional fields
(#1961-safe); the THREE Go-side §5.8 counters (alias confirmed-dropped,
alias quarantine-admitted, quarantine-overflow) are GO-side Prometheus
with no helper wire involvement (nine counters total).
Changed signatures are `pub(crate)`-internal only (the inventory is
honest about the full argument set, Codex r31 finding 4):
`match_source_nat_result_for_tuple` (+3: registry + worker id +
effective destination),
`match_source_nat_for_flow_result_at` (+3), `source_nat_decision_for_flow`
(+3), `source_nat_would_translate_fragment` (+1: registry only — probes
mint nothing and need no owner/occupancy),
`release_source_nat_allocation` / `rollback_source_nat_allocation` /
`reserve_synced_source_nat_allocation` (+registry + worker id +
owner/occupancy as applicable per call class),
`publish_shared_session` (+1: registry — Codex r4 blocker 5),
`remove_shared_session` (+1: registry), the coordinator test helper, the
nine release sites' call expressions, the new
`install_synced_with_reserve` wrapper at the three sync-family install
sites, a NEW narrow read accessor `translated_tuple_of(key)` on
`SessionTable` for the staged-replacement pre-read (`entry_by_key` is
private, session/mod.rs:1093 — Codex r5 blocker 1), the
`MaterializeConflict` outcome type for the materialize wrapper,
`release_all_worker_markers` at the worker-join teardown,
the registry bulk-release at the wholesale-clear site, the pool-allocator
authoritative `addr_index` + per-index live counter + drain carry-over key,
the address-only mint paths' `addr_index` correction, the tuple-versioned
`(flow, translated)` record key + secondary flow index inside the
interface registry's allocator instances, and the transactional
shared-replacement
alias sweep inside `publish_shared_session`'s displacement handling. Go changes: the #5144
validator extension (dedup-by-address), the snapshot-builder overlap
marking (source pools + NAT64 empty-pool + the §5.7 derivation matrix),
the receiver-side signature-drop rule + delete-suppression set
(§5.6), the six helper-side status-counter mirrors + Describe
registration, the THREE Go-side counters (confirmed-dropped +
quarantine-admitted + overflow), and tests.

## 7. Hidden invariants the change must preserve

- **Core ownership invariant**: every reachable session owns exactly one
  translated identity, held continuously from BEFORE it is reachable
  (decision-time mint; coordinator pre-reserve; reserve-before-install
  wrapper; publish-time {Shared}) until AFTER it is not (holder set
  empties: all workers + shared canonical row + teardown marker sweeps).
- **Probe purity (both classes)**: `non_first_fragment == true` OR
  `tuple_unknown == true` mints NOTHING.
- **Single-CS mint**: identity check + insert under ONE `live` mutex
  acquisition; the exact PAT probe chunks at 64 with yields, a LOCAL start
  ordinal, and ONE mutation-epoch retry.
- **Idempotent re-entry**: a second packet of the same flow returns the
  existing translation; no double-mint.
- **Release symmetry**: every mint frees through the existing teardown
  sites — no new delete site; rollback frees pre-install aborted mints;
  holder set empties before the identity frees; wholesale worker teardown
  drops all worker markers; wholesale shared clears iterate-and-release.
- **Never-steal**: synced reserve fails rather than evict a different
  flow's live identity; `IdentityConflict` ABORTS the reserve (tri-state),
  never falls through to a second domain.
- **Reserve-before-install everywhere**: local mint precedes install;
  worker wrapper reserves first (drop on failure, rollback on refusal);
  coordinator pre-reserve precedes publication; materialize reserve
  conflict returns `MaterializeConflict` to an explicit recycle/drop
  branch — NEVER a lookup miss and never the cold-admission path
  (Codex r5 major 4 / r6 minor 4).
- **Continuous holding across tuple change**: the staged replacement
  protocol (§5.6) on tuple-versioned records never frees T_old before it
  is unreachable on every scope — coordinator: pre-reserve T_new →
  canonical replace → alias sweep of the displaced entry → −{Shared};
  worker: pre-read → reserve T_new → install/replace → −{Worker}; each
  owner decrements only its own marker.
- **Drain discipline**: drain markers install BEFORE the worker-visible
  RuntimeView store; NEW mints on an address quarantine in EVERY domain
  while any generation holds live allocations on it (pool skips the
  address in its loop, NAT64 likewise, interface fails closed); reserves
  are never quarantined (but are tri-state); the drain lift is one atomic
  critical section (no resurrection); `addr_index` is authoritative in
  every mint path.
- **Registry lifetime**: node-lifetime; atomic `or_insert_with` creation;
  reclamation only when address-absent AND live-empty (apply-time +
  opportunistic); cap 256 RETAINED with its own counter; release
  LOOKUP-ONLY.
- **Invariant scoping (SMR r5 N16)**: "continuous holding" excludes the
  queue/relay-or-expiry-bounded reverse-companion edge
  (`replicate_session_delete` enqueues commands — no strict deadline),
  which is identical in shape to shipped pool-mode discipline today.
- **Fabric-alias discipline (v15)**: on the new+new path the SENDER
  omits derived forward-wire aliases entirely (additive pre-data
  `syncMsgCapability` frame with a fail-safe unknown→derive lifecycle —
  zero alias traffic, zero collateral, genuine self-NAT and
  identity-NPTv6 rows flow normally). On the legacy window the RECEIVER
  quarantines signature-matching upserts (full rewritten-tuple signature
  with the mandatory NAT64 exclusion and NO disposition gate — the
  cluster codec carries no disposition field, so non-fabric
  identity-NPTv6 rows also quarantine and timeout-admit), confirms
  aliases ORDER-AGNOSTICALLY (check the current store for a sibling
  canonical base at quarantine insertion — the sender queues base first
  on open — and only wait for the base's arrival in the lossy-reorder
  case), and ADMITS everything else on timeout through the complete
  normal import path (generation checks, timestamp rebasing, bulk
  bookkeeping, coordinator reserve, helper dispatch). Delete suppression
  begins at confirmation and clears when the first delete for the key
  after the base's delete is consumed (the alias's own delete, queued
  after the base's on close) or on a short bound; a genuine direct row
  sharing the key whose delete arrives while suppressed strands until
  its own session timeout — bounded, and strictly safer than today's
  certain publish-time clobber (shared_ops.rs:907). No alias row ever
  reaches the helper's ownership machinery unvetted; the base session's
  own derived forward-wire index row (shared_ops.rs:943-957) serves
  every lookup the alias row served, and the broken synthesized-companion
  churn (a live shipped hazard, shared_ops.rs:750 + nat/mod.rs:106)
  closes wherever the alias never forms.
- **NatDecision freeze**: no new fields; `rewrite_src_port: Some(_)` is
  handled generically everywhere from pool mode.
- **Hot path**: established-flow transit untouched; zero new per-packet
  work; admission-only registry locks; 1:N multimaps return to len-1
  inline buckets for interface SNAT.
- **Logging**: no per-packet logging; security-relevant events ride §5.8
  counters.

## 8. Risk assessment

| Class | Rating | Notes |
|---|---|---|
| Behavioral regression | LOW-MED | Wire change only for wire-ambiguous flows (later collider PAT'd); non-colliding flows byte-identical incl. sub-1024 ports and cross-dst port sharing. Overlap foreclose marks misconfigured pools unusable and DRAINS live ones (interface mints on the overlapping address fail closed during the drain — an availability pause on a previously-misdelivering path). Import drop-on-conflict sacrifices individual synced flows rather than their confidentiality. Tuple-changing re-sync keeps T_old held until unreachable. Pinned tests at session/tests.rs:4560/4602 stay GREEN (direct-install pins bypass admission) — one re-pointed at a live collision class, one annotated (§9). Mixed-version HA window documented (§5.4). |
| Lifetime / borrow-checker | LOW | Registry is `Arc<PortAllocator>` clones out of coordinator-owned `RwLock` maps; the SessionManager placement precedent. |
| Performance regression | LOW | Admission-only: registry write-lock create (first use per address) or read; one `live` mutex identity mint per NEW interface-mode flow; PAT probe only on collision (chunked); drain probe O(1) on quarantined addresses only; publish/remove +1 idempotent holder op per forward session lifecycle (cold paths); sync import +1 mint per entry on the coordinator (throttled sweep); zero per-packet cost. |
| Architectural mismatch | LOW | Built verbatim on the shipped #5269 token machinery + #5144 validator pattern + SessionManager placement + #4518 drain carry-over + #1760-W3' counter plumbing; no new subsystem, no packet-path scan. |

## 9. Test plan

- `cargo build` clean; full `make test-rust` and `make test-go`;
  `make test` umbrella. Fleet cap: build with
  `CARGO_TARGET_DIR=/home/ps/cargo-target/research-6751`.
- **PATH-A sole-writer transaction suite** (Codex r34 findings
  1-10 + major 11, Codex r36 minor 4, Codex r37 minor 4, AGY r32
  nit 2 — the consolidated §9 anchors for §4.0.1/§4.0.2):
  the COMPLETE writer inventory routes through helper
  transactions (including the #5305 pre-image rollback, the
  maps_sync initial-control cleanup, idle reaping with the table
  entry's id, and terminal teardown); bounded admission refuses
  at the per-worker bound with exact per-key errors and reserves
  capacity across all affected workers BEFORE any shared-state
  mutation; ONE end-to-end deadline with unknown-result = fenced
  receive epoch (no reconcile, no ACK, no hold release);
  the applied transaction's two ledgers with the five terminal
  outcomes (`Applied`, `AlreadyNewer`, `ConfirmedAliasNoop`,
  `Failed`, `Pending` — the ACK requires zero Failed/Pending,
  and a confirmed alias's intentional non-install is NEVER a
  failure); the delete transaction's table-authoritative
  predicate (mirror absence is safe only when no different live
  table entry exists); EXACTLY ONE close producer (the helper's
  commit; Go-initiated deletes are requests — refusal publishes
  nothing); the identity domains per transaction class; the
  stripe-guarded refresh RMW with named-field merge and singular
  counter ownership; the dual-lane Go-side arbiter (source
  admission + high-water + generation draw in one critical
  section per frame on either lane — the stalled-fallback-Close
  trace can never outdraw the event-stream Open; additive
  both-lane fields with fallback-disabled degradation;
  incarnation-validated watermark reset — restarted (E2,1)
  ACCEPTED after retained (E1,100)); sticky two-stage alias
  lineage across promotion/demotion/replication with export-path
  visibility; the copy-time identity binding for the bulk
  callback's omission decision; the helper-snapshot
  authoritative recovery source (SharedPromote included, alias
  excluded, full BulkStart/BulkEnd framing); the
  transport-refusal quiet interval with re-fence cycles; and the
  P2 purge in-helper with the no-close-toward-owner exception.
- **Failure-semantics pins** (Codex r36 minor 4 / r37 minor 4,
  made explicit after the r25-era fold audit): a worker reserve/
  install REFUSAL before the barrier ACK aggregates to `Failed`
  and FENCES the receive epoch — no reconcile, no ACK, no hold
  release, connection teardown; a P2 purge failure → `Failed`;
  a timeout/unknown purge or import result → `Pending` with the
  epoch fenced by teardown before any reconcile; the
  restarted-incarnation case (restarted (E2,1) ACCEPTED after
  retained (E1,100)); the stale-replica last_seen regression (a
  replica's older candidate never overwrites the owner's newer
  value — monotonic max(current, candidate)); S_new's reverse
  traffic resolving correctly on the peer WHILE S_old's stale
  reverse companion is still timing out (the adopted residual,
  verified end-to-end — AGY r32 nit 2).
- **Alias-stage propagation suite** (Codex r37 minor 3): a
  timeout-admitted `alias-suspect` row promoted to
  `SharedPromote` is NEVER exported while UNRESOLVED (the
  suspect mark rides the additive `SyncedSessionEntry` extension
  through the import request into the table metadata, is
  preserved by worker replication and by the promotion Open
  path — with the promotion Open itself GATED on the stage —
  and is checked by every exporter: promotion Open, owner-RG
  export, helper snapshot export, Go bulk, Go sweep); a genuine
  verdict at
  the definitive resolution pass clears the mark and the row
  exports normally; an alias verdict transitions it to permanent
  `alias-lineage`; the mark's stage is preserved across
  promotion, demotion, and re-promotion; and a concurrent export
  racing the verdict transition can never emit the row mid-
  transition (the mark update and the resolution verdict commit
  in the same critical section).
- **Retained-C0 degraded-terminal regression** (Codex r40 minor
  4): a legacy no-ACK peer retains C0 past a delayed/lost close
  notification (no plan-bounded kill — asserted, not assumed);
  the fence's degraded terminal is DISCONNECTED-ELIGIBLE (the
  connected-only 5s readiness timer never fires it,
  session_sync_readiness_test.go:33 intact); the release drives
  the sync-hold release path with the classic RETH VRRP 30s hold
  (manager.go:351) and the private-RG gate as the outer bounds;
  and the TWO debt terminals are asserted separately (delivery
  debt discharges at BulkEnd-ACK; the alias-proof debt persists
  until a capability-advertising definitive snapshot or the
  row's own close — never at a legacy both-empty transition).
- **Prime-request/re-fence liveness suite** (Codex r38 minor 5):
  timeout-admission of a suspect issues exactly one
  prime-REQUEST for it (coalesced across any number of
  outstanding suspects — one owed prime clears all at the
  definitive pass); a capable peer completes the owed prime and
  every suspect resolves at its BulkEnd; an old peer that
  ignores the field triggers the fence cycle (quiet interval +
  re-fence, bounded by the readiness timeout); multiple suspects
  coalesce into ONE fence cycle (a legacy-alias storm cannot
  become a tight re-fence loop); and the debt re-arms cleanly
  after a completed prime (the next suspect's timeout starts a
  fresh cycle, never inheriting a stale debt).
- **Pre-install children fence suite** (Codex r37 blocker 1 +
  r38 blocker 1 + r39 minor 4):
  every accepted child is generation-stamped AT `Accept`; fence
  engagement KILLS every pre-fence child (tracked setup children
  AND accepted-but-untracked ones) BEFORE the quiet interval
  starts (the drain clock starts only after those children are
  dead); a child whose fence generation predates the current
  fence is REJECTED at every later stage (beginSetup,
  finishSetup, installConn) — a stale child resuming after fence
  release is never stamped as a current admission; while the
  fence is ENGAGED, `Accept` REFUSES atomically (the engaged
  flag and the stamp are read/issued under ONE named admission
  mutex — Codex r39 nit 5: the admission linearization point is
  explicit, covering engaged-check, stamp issuance, child
  registration, the release-side generation advance, and
  disengage ordering, with advance-BEFORE-disengage required —
  distinct from the connection-state and setup-state locks,
  sync.go:301/322); the admission generation advances AGAIN at
  release after listener quiescence and a final sweep, so any
  residual mid-window stamp is stale at release; and the exact
  new trace is pinned directly:
  accept-after-sweep-start → resume-after-release (refused at
  admission — no stamp is ever issued mid-window), alongside the
  two original stalls: `Accept→beginSetup` and
  `finishSetup→installConn` (a child stalled at either seam is
  killed by the fence and rejected on resume).
- Alias-discipline abort/fence race tests (§5.6 contract, AGY r23 nit):
  install-between-detachments refused at clause (2); pending-frame-
  before-install discarded at clause (3); a stalled handler's post-reset
  frame discarded at clause (4); wedged-handler AbortFenceTimeout reset
  with a still-registered slot asserting both-nil + cold-prime arm at
  clause (5); nested abort re-arm at clause (5); blocked-I/O boundedness
  at clause (2b); large-bulk (10k-entry) boundedness at clause (2b);
  abort-mid-BulkSync partial-bulk disposition (no ACK, no reconcile,
  provisional installs converge at the next complete bulk) at (2b/i);
  a BulkEnd race at (2b/i); callback generation-race cancellation at
  (2b/ii) PLUS the detach-between-check-and-store case (impossible
  under the generation-tagged CAS) and the old-disconnect-after-new-
  connect case (the stale disconnect's write fails the CAS) — Codex r24
  blocker 1's two lifecycle races, one pinned per callback in the
  inventory (connect, disconnect, bulk-received, bulk-ack-received,
  readiness-timeout) — PLUS the equal-tag `true@G`/`false@G`
  overwrite regression (the C1-disconnect / C2-connect same-g
  collision: the stale equal-generation write MUST fail the
  strict-inequality tag CAS, AGY r25 blocker 1 / Codex r26 minor 3),
  PLUS the stale bulk-received event producing NO effects at all (no
  timer stop, no `ReleaseSyncHold`, no sync-ready marking — the
  failed tag CAS suppresses every associated effect atomically,
  Codex r25 blocker 1's second half / Codex r26 minor 3), PLUS the
  readiness-timer stalled-after-validation case (the expiry event
  passes arming-generation/connected validation, stalls, a newer
  disconnect/cold-start transition commits readiness false, and the
  stalled event's commit then loses the tag CAS — `SetSyncReady(true)`
  NEVER executes, Codex r26 blocker 1);
  journal/delta race tests: per-key #2170 ordering covers upserts AND
  deletes via tombstones (sync_conn_gen.go:179-322), PLUS the
  sender-cap / receiver-cap / zero-generation delete-install reorder
  cases, PLUS a directly-queued raw-byte delta dequeued pre-abort and
  sent on a REPLACEMENT connection (discarded by the epoch-bound send
  guard), PLUS an already-dequeued retry crossing the abort boundary
  (same guard), PLUS the queued-behind-A case (delta B enqueued under
  epoch N behind delta A, still QUEUED when the abort lands, dequeued
  only after the replacement connection N+1 is up — B's envelope says
  N and the sendLoop discards it; B NEVER travels on N+1, Codex r25
  blocker 2 / Codex r26 minor 3), PLUS a routine no-prime
  single-fabric flip RETAINING all pre- and mid-flip deltas (the
  compared epoch does not advance where no authoritative prime is
  scheduled, sync_conn.go:178/208 — the delta stream itself is the
  authority, Codex r25 blocker 2 / Codex r26 minor 3), PLUS the
  prime-barrier ordering case (a cold-prime bulk never emits `BulkEnd`
  after a dropped or stale bulk frame: the epoch barrier drains the
  delta queue before the bulk writes losslessly under the new epoch,
  and any bulk frame write failure aborts the bulk BEFORE `BulkEnd`
  — Codex r26 blocker 2), PLUS the content-version binding cases
  (Codex r27 blocker 1, before/between/after: a batch-copied
  `K=V_old` overtaken by a close/replacement that drew `G1` is NEVER
  written with `G2 > G1` — the callback re-reads live under the
  generation-map lock and the frame carries the recorded `G0`, so
  delta-first the stale `G0` frame is refused and bulk-first the real
  `G1` corrects the provisional install; a vanished K omits its frame
  and converges via tombstone + BulkEnd reconcile; a live-value
  mismatch mints fresh for the CURRENT content; and the
  `QueueSessionV4` stamp→encode→queue window — an abort between
  generation stamp and enqueue leaves the envelope at the OLD epoch,
  discarded on the replacement connection), PLUS the
  producer-ordering invariant (Codex r28 blocker 1: for a Close the
  mirror row is deleted BEFORE the close publishes on any channel —
  a Go close-consumption (tombstone drawn, generation record removed)
  implies the mirror already lacks K, so the bulk's live re-read
  takes the V3 omit branch and the durable tombstone + BulkEnd
  reconcile converge the receiver in BOTH wire orders; the reverse
  order (publish-then-delete) is a pinned regression RED), PLUS the
  incarnation-conditional delete (Codex r29 finding 1 / AGY r30
  findings 1-3 / Codex r31 finding 1: a queued old Close whose key
  has been reinstalled as K' does NOT delete K''s mirror row — the
  compare-and-delete matches the row's stored #5213 session_id,
  serialized against same-key publish by the striped per-key
  producer mutex (the TOCTOU lookup→migrate→delete trace removes
  nothing); the expiry-early-delete / replacement-republish /
  flush-time-delete trace at loop_body/mod.rs:958/:1027/:1230 keeps
  the replacement even under a worker-migration steering change;
  the stale close is SUPPRESSED ENTIRELY — no delete, no
  publication, no generation draw — so the fatal inverse (G_del >
  G_new tombstoning the live replacement at the peer) never forms;
  the tunnel purge and terminal teardown supply the closing entry's
  id (never hardcoded 0, tunnel_purge.rs:69 / session/install.rs:495)
  and the purge uses the real conntrack FDs;
  and a row published
  before #5213 (legacy zero session_id) NEVER matches a closing id —
  the safe direction: the tombstone still conveys the close and the
  sender-tombstone omits the stale row from bulks — pinned so a
  future refactor cannot "fix" it into matching, SMR r31), PLUS the
  failed-delete omission index (Codex r31 finding 2: a mirror row
  that survived a failed delete is OMITTED from every bulk while its
  omission entry stands — never re-minted into a peer-side zombie —
  and at index overflow the owed prime runs as the TABLE-TRUTH
  export, never trusting the dirty mirror), PLUS the
  carry-forward overflow direction (Codex r31 finding 3: overflow
  forces a FENCED INBOUND re-prime with a reconciliation HOLD on the
  overflowed episode — never the outbound forceResync boolean —
  and the deferred-alias liveness contract is the same re-prime's
  definitive BulkEnd, Codex r31 finding 8), PLUS the
  carry-forward retention case (AGY r30 finding 4: BulkEnd1 → delta
  D1 → BulkStart2 → abort → BulkStart3 → BulkEnd3 keeps D1 carried
  and reconcile never deletes it — the accumulator clears only on a
  COMPLETED BulkEnd; the capped-overflow arm drives forceResync),
  PLUS the received-set carry-forward (an Open consumed
  immediately before BulkStart with a mirror-write hole is rescued
  by carry-forward; a key legitimately closed in that window is NOT
  resurrected — its strictly-greater tombstone deletes it), PLUS the
  known-stale omission (Codex r28 major 6: a close/replacement
  consumed between the live re-read and the bind advances the
  recorded generation inside the same critical section — the frame
  is NOT written, and the advancing event's own channel re-conveys:
  journaled delete, or backfill-armed sweep re-send), PLUS the
  universal producer atomicity regression (Codex r28 major 5: a
  first-offer draw racing a bulk mint can never overwrite the map
  with an older generation — draw, epoch capture, and record are one
  critical section per producer, RED on the draw-before-lock shape at
  sync_conn_gen.go:119), PLUS the debt machinery (Codex r28 blocker
  2: a barrier-aborted prime's debt survives SessionSync teardown
  and is INHERITED by the replacement's first connection; discharge
  is exact-generation compare-and-clear on BulkEnd-ACK — an older
  async completion never clears a newer abort's debt (second-abort/
  older-completion race); a cold-prime attempted with no runtime
  attached DEFERS and re-arms (never fails sessions==nil, never
  discharges); the readiness timeout releases the hold but NEVER
  clears the debt), PLUS the debt attribution/terminal cases (Codex
  r29 finding 6: two outstanding primes attribute ACKs by the
  (bulk epoch → debtGen) pair — a non-current ACK is ignored for
  debt purposes; a chassis-cluster-disable teardown with no
  replacement CLEARS the debt), PLUS the equality-projection cases
  (Codex r28 minor 7 / r29 finding 11: a LastSeen/policy_id/counter-
  only mirror refresh does NOT force a fresh mint; a FIB/tunnel/
  ALG/flags/zone drift DOES), PLUS the sweep-wake case (Codex r29
  finding 10: the syncBackfillNeeded arm RESETS the sweep timer —
  the re-send bound is the sweep cycle, not the 10s backoff
  ceiling), PLUS the registry-cap fail-closed case (Codex r29
  finding 8: allocator_for at the 256 cap with no reclaimable
  allocator refuses admission with the dedicated counter, never
  exceeds the cap), PLUS the index-cardinality case (Codex r29
  finding 5: a bulk carrying >4096 ordinary non-fabric SNAT rows
  does NOT abort — the bulk-epoch index is bounded by the received
  set, and the incremental-window cap DEFERS excess alias entries to
  the next bulk's BulkEnd resolution — a deferred real alias never
  installs a broken companion, AGY r30 finding 5), PLUS the confirm-and-purge cases (a
  timeout-admitted alias later re-received confirms and its admitted
  row is locally deleted — no stale companion survives the later
  bulk; a timeout-admitted alias is PROVISIONAL — the next completed
  BulkEnd purges it against the definitive snapshot even when no new
  alias frame ever arrives, Codex r30 finding 2; and the purge is
  exact-publication compare-and-delete — a genuine direct
  replacement row at the alias key SURVIVES, Codex r30 finding 6),
  PLUS the id-preservation case (a promoted standby's re-bulk
  encodes the received RTFlowSessionID from its sync-side record —
  the downstream receiver confirms the base+alias pair, never
  admits the alias, Codex r30 finding 6), PLUS the
  import-driven-creation case (a fresh standby's synchronized
  reserve creates the egress allocator and reserves the imported
  identity; after failover the first local mint on the same
  occupancy PATs instead of preserving the already-live imported
  identity, Codex r30 finding 4; PLUS the 257th synchronized import
  fails closed with the registry-cap counter, and an import arriving
  while a prior domain is draining routes to the draining allocator,
  Codex r31 finding 10), PLUS the purge-generation case
  (the tunnel-remap purge/GC helper-local delete draws a tracked
  tombstone generation — gen-0 remains only for genuinely untracked
  keys, Codex r30 finding 1), PLUS the pre-dispatch attribution
  assertion (a barrier pre-start abort records NO
  (bulk epoch → debtGen) pair — the pair exists only from dispatch,
  Codex r30 nit 7), PLUS the
  authoritative-recovery case (a barrier-aborted prime re-drives ONLY
  the lossless direct-write `doBulkSync` or a fenced-reconnect
  cold-prime — the event-stream exporter path is NEVER used for the
  owed authoritative prime, the abort does not consume the episode
  latch, and the owed state survives until an authoritative prime
  completes — Codex r27 blocker 2), PLUS the unconditional
  timer-invalidation case (`stopClusterComms` with ss==nil still
  bumps the arming generation — Codex r27 minor 3), PLUS the persistent-cap self-rearm case
  (the recovery bulk cannot arm its successor; the episode latch
  permits one bulk per cooldown window), PLUS a zero-generation
  envelope bound to the fresh post-abort generation intentionally
  admitted into the documented unordered class and pinned through the
  following authoritative bulk (Codex r24 minor 4).
- New unit tests (nat/source.rs + allocator):
  preserve-first success; collision → PAT (distinct identities, distinct
  `reverse_wire_key`s, both flows' replies resolve to their OWN forward
  session); same port different servers BOTH preserve; TCP vs UDP same
  numeric port BOTH preserve; source port < 1024 preserved; ICMP same-id
  pair → second id translated; port-less GRE → token, second collider
  fail-closed; COMPOSED-DNAT collision (Codex r28 blocker 3 / r29
  finding 3: `VIP:80` and `VIP:81` both DNAT to `backend:8080` and share
  the interface-SNAT egress — the two flows keep DISTINCT owner tuples
  (original destination) but ONE occupancy tuple (effective
  destination), so the first flow preserves and the second PATs, and
  both flows' replies un-NAT to their OWN forward session; PLUS the
  idempotence regression: re-admission of the SAME owner flow
  (`H:5555→VIP:80` again) hits its owner tuple and does NOT PAT;
  PLUS whole-address static occupancy (directions per the §5.7 norm:
  static-FIRST — the static holds the occupancy — makes the arriving
  INTERFACE flow PAT; interface-FIRST makes the arriving STATIC flow
  fail closed with its OWN static conflict counter, never the
  interface exhaustion counter; a MAPPED-PORT static reserves the
  EMITTED external source port — the `8080→80` case reserves
  `E:8080`, not `E:80` (static_nat_mapped_port_2491_test.go:20,
  Codex r31 finding 5); the INBOUND static-DNAT decision point
  acquires occupancy for inbound-created sessions; config removal
  DRAINS the static holder — live sessions keep their tuple until
  close, interface mints quarantine until the drain completes; and
  the commit validator rejects/warns the
  static-on-iface-egress config per the §5.7 arm);
  EXACT probe (local start ordinal: full cycle finds the one
  free candidate among shaped contiguous occupied runs — RED on the v2
  4096-budget design; genuine per-destination saturation → exhaustion;
  registry-cap vs per-destination exhaustion distinguished; concurrent
  mint/free with the mutation-epoch retry); idempotent re-entry;
  cross-rule same-egress collision detected; BOTH probe classes mint
  nothing; rollback frees; reserve_synced tri-state (NotThisDomain /
  Owned / IdentityConflict — the Codex r4 counterexample: draining pool
  owns T, interface import of T aborts, never falls through); nat64
  decisions bypass the source/interface scan; addr_index authoritative in
  every address-only mint path (pool [A,E] address-only flow on E counts
  against E, not A); tuple-versioned records (a flow holds T_old + T_new
  transiently during staged replacement; release matches (flow,
  translated) exactly; a different-tuple record is removed only by an
  explicit holder release when its holder set empties (never auto-dropped
  by a reserve — Codex r6 major 2 / r7 nit 6); transactional
  shared replacement (canonical replace sweeps the displaced entry's
  aliases — reverse_wire/reverse_canonical/forward_wire of T_old no
  longer resolvable — with COMPARE-AND-REMOVE ownership validation so a
  third-party occupant of T_old's derived slot is never swept — Codex r7
  major 4); fabric forward-wire alias discipline (new+new: a sender
  honoring the receiver's additive capability advertisement SKIPS the
  alias derivation branch entirely — zero alias upserts AND zero alias
  deletes on the wire, genuine self-NAT and identity-NPTv6 rows flowing
  normally with NO collateral (Codex r13's own "negotiated sender-side
  alias omission"); legacy window: signature-matching upserts QUARANTINE
  in pkg/cluster after decode before bulkRecv bookkeeping
  (sync_conn_read.go:110 ordering) — the full rewritten-tuple signature
  (forward ∧ sync-derived ∧ SNAT flag ∧ NOT NAT64 — decoded Nat64SnatV4
  exclusion per Codex r13 blocker 2, since a v4 NAT64 rewrite reformats
  as an IPv6 address and a legitimate NAT64 client at that address would
  otherwise match — ∧ key.src_ip ==
  rewrite_src ∧ (key.src_port == rewrite_src_port OR rewrite_src_port ==
  0) — the full-tuple term per Codex r13 major 3a, so bijective
  same-address PAT and same-IP static mapped-port sessions never match;
  NO disposition gate per Codex r14 blocker 1 — the cluster codec
  carries no disposition field, so non-fabric identity-NPTv6 rows also
  quarantine and timeout-admit);
  bulk bookkeeping is NOT gated (AGY r15 blocker 1 — quarantined keys are
  still recorded as received at decode time, so
  reconcileStaleSessions/ReconcileClusterBulk at BulkEnd never deletes a
  genuine self-NAT or identity-NPTv6 session as stale ~50ms after the
  bulk, before its 5s timeout admission could run; and the timeout
  admission's bookkeeping touch is guarded on a bulk being open — after
  BulkEnd the map is nil'd, sync.go:1090, so an unconditional write
  would panic);
  confirmation is ORDER-AGNOSTIC (Codex r14 blocker 2 — the sender queues
  the base FIRST on open, daemon_ha_userspace_stream.go:370/375/384, so
  the quarantine checks the bounded decode-time BASE-IDENTITY INDEX for a
  sibling canonical base at INSERTION: forward-wire relation + identical
  decision + equal NON-ZERO RTFlowSessionID — populated at decode where
  the ID IS present, since the store-delegating read can never return it
  (RTFlowSessionID is sync-only, absent from the BPF ABI, types.go:114 /
  bpf_session_value.go:204 — Codex r28 blocker 4; the base-first normal
  case MUST confirm through the index, RED on any store-read predicate)
  — and only waits for the base's arrival in the lossy-reorder
  alias-first case) → confirmed entries dropped +
  delete suppression that clears only when the FIRST delete for the key
  AFTER the base's delete is consumed (the alias's own delete — the
  exporter queues base-delete before alias-delete on close,
  daemon_ha_userspace_stream.go:398/403) or on a short bound;
  every quarantined entry RESOLVES AT ITS OWN BULK'S BulkEnd (Codex r15
  blocker 1 — no cross-epoch deferral: at BulkEnd the complete snapshot
  makes the sibling-base check definitive — still-matching entries with
  a sibling in the received set CONFIRM-alias and drop; everything else
  is ADMITTED through the complete normal import path — generation
  checks, timestamp rebasing, bulk bookkeeping, coordinator reserve,
  helper dispatch — in the same serialized pass BEFORE the bulk ACK and
  sync-hold release (sync_conn_read.go:240/244), so the receiver never
  ACKs while a genuine row is unresolved; incremental-delta entries
  (outside any bulk) resolve on a 5s fallback timer (disposition
  ONLY — the timer admits but NEVER clears lineage; a
  fail-on-timeout-clear regression pins that an admitted suspect
  keeps its mark — Codex r38 major 3) against the CURRENT store
  (which is disposition-definitive only, never lineage-definitive
  — Codex r39 nit 6's wording cleanup); ALL quarantine actions run as events on the
  receiver's SERIALIZED event loop — a timer only enqueues a wakeup,
  since the generation-check/install/record sequence is safe only
  single-threaded, sync_conn_gen.go:381)
  for the genuine self-NAT, identity-NPTv6 (no alias is ever derived
  for it, daemon_ha_userspace_convert.go:511), and lost-base cases
  (plus the Codex r16 lifecycle rules folded above: quarantine-cap
  OVERFLOW aborts the incomplete bulk without ACK (no eviction —
  payloads are not retained past decode) and its pinned entries drop
  fail-closed; a STALLED bulk hits the new per-bulk receive deadline
  and aborts the same way; a SUPERSEDING BulkStart drops the prior
  epoch's pinned entries fail-closed before overwriting the maps);
  the implementation parameter summary for the alias discipline:
  quarantine cap (4096, tunable per deployment at provisioning),
  incremental-delta fallback timeout (5s), AbortFenceTimeout (a small
  multiple of the disconnect callback's normal latency — AGY r19 nit),
  per-bulk receive deadline (new, default 5-10s scaled to the bulk
  size floor, named at implementation — AGY r28 nit 1), the
  abort-triggered per-peer reconnect backoff (base/cap, abort-only),
  the incarnation-gate stripe count (1024-4096 `Mutex<()>` entries
  indexed by key hash — AGY r32 nit 1),
  AND the epoch-barrier drain bound (default 2-5s, named at
  implementation — AGY r27 nit 1);
  a genuine direct row sharing the key whose delete arrives while
  suppression is active strands until its own session timeout
  (documented residual, strictly safer than today's certain
  publish-time clobber, shared_ops.rs:907); three Go-side counters
  (confirmed-dropped, quarantine-admitted, overflow); V4 AND
  V6 parity — AGY r10/r11 nit; `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS`
  no longer fires per sweep for a fabric-redirect SNAT session wherever
  the alias never forms — the pre-existing
  companion-displacement churn is gone — Codex r10/r11/r12 blockers
  resolved by removal); staged replacement
  (T_old held until unreachable;
  each owner drops only its own marker); uniform mint quarantine (a
  re-enabled edited pool cannot mint an identity an older draining
  generation owns — pool skips quarantined addresses in its address loop,
  interface fails closed; EVERY fixed-address mode fails closed when its
  selected address is quarantined, enumerated as separate test cases —
  address-persistent/sticky single-probe, port-translating persistent-NAT
  pinned-lease decision (allocator.rs:1114), address-only persistent
  (allocator.rs:1955), deterministic CGNAT (allocator.rs:1482),
  deterministic NAT64 (allocator.rs:1561) — Codex r7 minor 5 / r8 minor 3);
  materialize conflict returns
  MaterializeConflict (explicit recycle/drop branch, NEVER the
  cold-admission miss path — Codex r5 major 4); tuple-
  versioned secondary flow index (local mint re-entry returns the flow's
  locally-minted record across the staged overlap; reserve NEVER
  auto-drops a different-tuple record — Codex r6 major 2); holder completeness
  (sibling replica reap does not free the owner's identity — RED on the
  #6522 shape; replay re-reserve is a no-op; all-workers-reap with live
  shared canonical row does NOT free; materialize acquires via the wrapper;
  local publish acquires {Shared}; coordinator
  pre-reserve conflict drops the import; RESERVE-BEFORE-INSTALL: the
  delete/upsert/local-mint race leaves NO installed-unreserved duplicate;
  worker-join teardown drops all worker markers; stop_inner(false)
  reconcile replay re-acquires; wholesale clear iterate-and-releases every
  {Shared}; stop→rebind with a held identity); drain quarantine (overlap
  marked unusable; live pool session keeps its tuple in the draining
  allocator; interface mint on the address fails closed; drain completes →
  atomic lift → mints proceed; pool EDITED mid-drain → releases still
  reach the draining allocator via the drain-vec scan — AGY r4 major 2).
- Go validator tests: dedup-by-address (two interface rules, one WAN
  address → NO false rejection); interface-vs-source-pool overlap → strict
  reject + tolerant warn; interface-vs-NAT64-pool overlap → same;
  no-overlap pass.
- Go builder tests (the §5.7 derivation matrix): overlap via `to-zone`,
  via `to-interface`, via `to-routing-instance`, via UNSCOPED to-side
  (wildcard = all interfaces) — each marks the pool unusable / NAT64 pool
  empty; RUNTIME-resolved address (mocked buildLinkSnapshot); non-overlap
  unchanged.
- Existing pins: session/tests.rs:4560/4602 stay GREEN; ONE re-pointed at a
  live non-bijective class (DNAT-to-shared-backend), the OTHER annotated
  that direct-install bypasses admission; #4399/#4438/#5269/#5336 suites
  unchanged.
- Smoke (loss userspace cluster, lock protocol per CLAUDE.md): two test
  hosts behind interface-mode SNAT, same source port to the same target —
  both flows establish, distinct external ports on the WAN side (tcpdump),
  replies land on the correct host; same-id ping pair both get replies;
  `make test-failover`; bulk-sync/failover pin for the
  two-legacy-flows-one-identity import case (first reserves, second drops,
  failover kills only the second); helper-restart rehydration via HA
  re-sync pre-reserve.
- Counters: the nine §5.8 counters (six helper-side + three Go-side) bump exactly on their events;
  a unit test asserts `prometheus.MustRegister` coverage for all nine
  counter descriptors (no registration panic, no silent omission — AGY
  r26 nit 2; scoped explicitly: the THREE Go-side cluster counters in
  pkg/cluster AND the SIX helper status-counter mirrors registered
  via pkg/api/metrics.go — AGY r34 nit 5);
  `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS` stays flat for the interface
  class.
- Docs sweep: docs/userspace-dataplane-architecture.md,
  docs/userspace-dataplane-gaps.md:44 row, `_Log.md`.

## 10. Out of scope (explicitly)

- Pool allocator holder fix (#6522) — the new registry ships with the
  holder model; pool keeps its known exposure until #6522 lands.
- Junos-literal always-PAT — larger wire change, no correctness gain.
- Config knobs for the interface-mode port range (fixed 1024-65535);
  registry occupancy/holder introspection (§5.8 follow-up).
- Quarantine-with-retry for import conflicts (adjudicated §5.6).
- #2387 session-identity enrichment — orthogonal; the colliding flows share
  every context.
- DNAT-to-shared-backend / NAT64 / static NON-BIJECTIVE classes — covered
  by the shipped 1:N multimaps. (Whole-ADDRESS port-preserving static is
  NOT in this class: its flows can collide with interface-SNAT occupancy
  on one wire identity — enumerated as a cross-domain owner in §5.7 per
  Codex r29 finding 4.)
- NAT64 fabric forward-wire alias ownership — NAT64 decisions bypass the
  interface registry (§5.3); their alias reserves keep today's
  never-steal graceful-skip. The cross-family alias-reconstruction
  concern (an alias deriving a different NatDecision from the padded v6
  slot, codec/wire.rs:182 + server/helpers/session_sync.rs:47) is a
  PRE-EXISTING NAT64-sync question, named here as a follow-up candidate
  (Codex r7 blocker 3, scoped out with the reviewers' option to re-open).
- ALG payload rewriting for PAT'd ports; netflow/syslog translated-port
  fields (already generic per §4 item 4 audit).

## 11. Open questions for adversarial review

1. Core invariant (top of doc, as scoped by SMR r5 N16's reverse-companion
   relay-lag note): name ONE remaining lifecycle path where a reachable
   session does not own its identity — the r4/r5 inventory (publication,
   tuple-changing re-sync on tuple-versioned records, drain transition
   with uniform mint quarantine, worker teardown, reconcile replay,
   transactional shared replacement with the derived-index sweep) is now
   covered in §5.3/§5.6/§5.7, and the fabric-alias class is removed from
   the ownership design entirely (§5.6, v11).
2. The v14 alias discipline (negotiated sender omission on new+new;
   receiver-side signature quarantine on the legacy window) rests on
   three verified claims: the explicit alias row is redundant with the
   base's derived forward-wire index row (walked independently by AGY
   r9/r11/r12/r13 and Codex r9/r10/r11/r12/r13); the full rewritten-tuple
   signature with the NAT64 exclusion and NO disposition gate (the
   cluster codec carries no disposition field, so non-fabric
   identity-NPTv6 rows also quarantine — Codex r14 blocker 1's priced
   consequence) false-positives on NOTHING except genuine self-NAT rows
   AND non-fabric identity-NPTv6 rows in the legacy window, and those
   are ADMITTED after the quarantine timeout (a delay, not a drop); and
   the base-lifecycle delete suppression is strictly safer-or-equal to
   today in every matrix cell (today the alias upsert clobbers a
   same-key occupant at publish with certainty, shared_ops.rs:907).
   Falsify any of the three with a consumer of the explicit alias row
   the derived row does not serve, a NAT class where the full signature
   still false-positives, or a delete-ordering where the
   base-lifecycle-keyed suppression strands a genuine row past its
   timeout. The capability transport is now fixed (dedicated periodic
   syncMsgCapability ticker, no alternatives) — is there any receiver
   state machine in pkg/cluster whose periodic cadence the ticker
   should SHARE rather than duplicate?
3. Tuple-versioned records (§5.3): confined to the interface registry's
   allocator instances, with pool allocators keeping today's flow-keyed
   shape and free-on-release semantics. Is the two-shape split coherent,
   or should pools adopt the tuple-versioned shape uniformly (which
   entangles #6522's open holder question)?
4. Uniform mint quarantine (§5.7): pool admission skips a quarantined
   address and tries the next pool address — graceful for multi-address
   pools, exhaustion when all are quarantined. Is skip-next the right
   pool-side posture, or should pool admission fail closed on the rule
   (like interface) while any of its addresses drains?
5. Preserve-first vs Junos-literal always-PAT: does any reviewer still
   demand literal parity?
6. Mixed-version window (§5.4): accept, or gate `SessionSyncProtocol`?
7. Is PLAN-KILL (option (c)) defensible for a High security finding given
   the mechanism is ~verbatim reuse of shipped machinery?
