# DRAFT v6 — Fix plan for #10512: commit invalidation misses deleted tenant on bare 5-tuple mirror collision

Status: DRAFT v6 (helper-first cross-process tuple-gate cutover, clear-fence
ordering and continuation ownership, restart identity-index quarantine,
HA-import race proof, and Delta1 NR-1/NR-2/NR-3/NR-4 plus Delta2 NR-5/NR-6
corrections; no production code in this commit).
Issue: #10512 (OPEN, bug + audit + validated-by:research + source:deep-review).
Base: `5dcaa104fb36637f7b76bdd0b3ba26ea880f1046` (`origin/master` after
rebase); prior plan base `2781465ee3afe52a780d94d2245cb565a1e80548` and v1 tip
`4d2cb2bf6` remain in history.
Lane: Eng10512. Date: 2026-09-22.

## 0. Plan-review fold (round 1 → v6)

Round-1 verdicts on v1 (both read in full): Rev10512PlanA PLAN-NEEDS-MAJOR
(F1 mirror GC, F2 bare HA-sync, F3 frozen/admissions, F4 two-phase, F5 fan-out,
F6 test coverage, F7 guards, F8 skew fallback, F9 version, F10 blast-radius,
F11 B1 feasibility); Rev10512PlanB PLAN-NEEDS-MAJOR near-KILL (F1 HA leg,
F2 mirror lifecycle, F3 predicate/admissions, F4 placement, F5 fan-out/skew,
F6 tests, F7 decided-questions). Convergent: miss mechanics verified, Option A
direction sound, contracts to close the miss on every path not specified.

Fold-2 (Delta2): Delta1's PLAN-READY findings remain unchanged. Delta2 R1
adds bounded tuple-gate permits, finalization, liveness, and proof in §2.2;
R2 adds bounded delete batching, deadlines, completion, and #5578 mapping in
§2.4/§4. Delta2 R3–R6 are deferred per the parent brief.

Fold-3 (V4): Delta2 R1's cross-process objection is closed by a helper-first
  migration, not a direct Go BPF lease. Every production Go `bpfShim` session
  mutation caller is cut over to a helper-first mutator; the helper derives
  forward+reverse keys, acquires the bounded tuple gate, and performs
  SessionTable/BPF mutation in one process. HA-import upsert, reverse-only
  publish, #5305 compensation, restart epoch, and the HA-import race proof are
  pinned in §2.2 and §5; no paused Go caller can resume a stale BPF syscall.
Delta1's NR-1 positive-empty contrast, NR-2 mixed-version skew sentences, and
NR-3 within-commit retry/convergence correction are folded in §1.2, §2.4, §4,
and §5.

Fold-4 (V6; Delta1 NR-4, Delta2 NR-5/NR-6): clear-all contract re-pins
target `mirror_clear_chunk`; shared `ClearAdmission` orders tuple `GateLease`s
against the full-continuation `ClearFenceID`; and restart quarantine rebuilds
the `SessionTableIdentityIndex` with orphan accounting. The §5 matrix now
covers clear-fence/delete-import interleavings, mid-`Finalizing` fencing, and
post-dispatch `unknown_outcome` reissue semantics.

Parent SOURCE-DETERMINED closures (closed in this revision, not re-asked):


| Q | Ruling | Closed in |
|---|--------|-----------|
| Q1 verb shape | READ verb `list_sessions_by_policy`; Go orchestrates scoped deletes + HA + logging (a single helper discover+delete RPC cannot satisfy capture-READ + delete-after-live) | §2–§4 |
| Q2 old-numbering | Go passes OLD id sets; helper scans FROZEN install ids | §3 |
| Q3 bounds + lock | Budgeted/chunked like refresh/export, kick/collect, never hold ServerState across scan; worst case + timeout stated | §4 |
| Q4 failure | NO mirror fallback; fail closed as #5578 commit error | §4 |
| Q5 standby | YES, standby coverage required (delete-sync as today does NOT suffice) | §1 |
| Q6 B1 end-state | OPEN as follow-up tech-debt filing only (needs shim-domain feasibility proof first) | §8 |

Boundary honored: HA-wire/standby is IN scope (§1) and mirror preservation is
specified with a B-visibility proof (§2). No `GC will heal` claim anywhere:
the refresh path writes with `BPF_EXIST` specifically so it will not recreate
a deleted entry (`userspace-dp/src/afxdp/bpf_map/mod.rs` refresh;
`pkg/dataplane/userspace/manager_sessions.go:620-622` "Silence is not assent").

## 1. HA design: domain-carrying cross-node delete (required block 1)

### 1.1 Why the current wire cannot close the failover leg (grounded)

- Primary sends bare deletes: `pkg/daemon/daemon_policy_invalidate.go:560,576`
  `ss.QueueDeleteV4(e.Key, false)` / V6 twin — bare `SessionKey` only.
- `pkg/cluster/sync_conn_write.go:194` `QueueDeleteV4(key, forwardOnly)`:
  `gen := s.takeDeleteGenV4(key)` (:201) — generation keyed by BARE tuple, so
  colliding tenants share one generation space — then `encodeDeleteV4` (:202),
  journaled on disconnect (`s.journalDelete(msg)`).
- `pkg/cluster/sync_protocol.go:479-523`: delete = 16-byte (v4) / 40-byte (v6)
  tuple + trailing #2170 generation u64 + one #9752 forwardOnly byte. NO
  domain. Installs DO carry `RoutingDomain` (reviewer-verified
  sync_protocol.go:269,435,742,928; corroborated by measured upserts
  `docs/log/9146.md:20-21` and the `SessionSyncRequest.routing_domain` field).
- Standby applies bare:
  `pkg/cluster/sync_conn_gen.go:1203-1227` `deleteClusterSyncedV4` →
  `s.sessions.DeleteWithCompanionsV4(bare key, ClusterStale)` (:1223), and
  `delete(s.installTableRecvV4, key)` (:1220-1222) — received-identity ALSO
  keyed bare, so colliding tenants share that record too.
- `pkg/dataplane/session_store.go:888-899`: `GetSessionV4(bare)` returns ONE
  row (the standby's own bare-mirror last-writer) and deletes with THAT row's
  domain; on miss, bare peer-delete probes every instance and is REFUSED when
  two tenants match (`userspace-dp/src/server/handlers/sync_session.rs:257-273`
  probe, `:304-315` ambiguous refusal, #8636).
- `docs/log/9146.md:27-40`: a tenant swap emits 2 upserts + 0 deletes; the
  standby accumulates both rows (proven by
  `state_holding_the_same_tuple_in(&[100_007, 100_008])` → 4 rows).

Trace of "HA-sync as today": primary deletes A locally, sends bare
QueueDelete; standby holds synced A+B; its bare `GetSessionV4` returns B
(deletes B, keeps A: over+under), or misses and the bare peer-delete is
refused (under), or returns A by ordering luck. Failover then resurrects A
and/or loses B. Q5 is therefore NOT empirical — the wire + probe prove it.

### 1.2 Design: widen the delete wire (chosen over standby-verb RPC)

Rationale: delete-sync journaling, replay, generation guards, and
bulk-reconcile already ARE the cross-node channel. A separate standby verb
RPC would duplicate journaling + promotion-race handling; the widened wire
keeps Go as orchestrator (Q1) with one channel.

- Wire: append length-gated `routing_domain` u32 and expected
  `expected_rt_flow_session_id` u64 after the forwardOnly byte in
  `encodeDeleteV4/V6` (v4 payload 37 bytes, v6 payload 61 bytes; old decoders
  stop after bytes they know — same length-gated discipline as the #2170
  generation and #9752 marker). A domain delete conditionally removes the
  forward half when that RT_FLOW id matches; once it matches, the peer derives
  its own reverse companion. The local-only companion identity is never put
  on the HA wire. A legacy delete without domain/id keeps bare behavior
  (single-tenant fast path, non-policy sweeps).
- Generation per (domain, tuple): `takeDeleteGenV4/V6` and
  `deleteGenGuardV4/V6` keyed by scoped identity; `installTableRecvV4/V6`
  keyed by scoped identity. Migration note: in-flight bare records from a
  mixed-version window are treated as unknown-generation; legacy fallback is
  permitted only for explicitly bare non-policy records, never authoritative
  for a scoped policy delete. Implement lane pins the exact map-key migration.
- Version floor + skew/withhold: new cluster-sync capability bit + MinProtocol
  gate (precedent: `suppressDeleteForIncapablePeer` #9714,
  `suppressForwardOnlyDeleteForIncapablePeer` #9752 at
  sync_conn_write.go:208-233). For an incapable peer the domain-carrying
  delete is WITHHELD (counter + one-shot warn + operator guidance), leaving
  the session to idle out — the same visible-leak-over-invisible-teardown
  trade the #9752 suppressor makes. NEVER downgrade a colliding-tuple delete
  to bare: bare would refuse (safe under-clear, but silent-looking) or
  mis-delete (over+under). Withhold is explicit and counted.
- Standby apply: `deleteClusterSyncedV4/V6` with domain +
  `expected_rt_flow_session_id` → the same helper-first, collision-aware
  scoped delete used by §2 (no bare `GetSession` first and no ambiguous
  probe); it deletes only when the current `(domain, tuple)` helper row has
  that RT_FLOW identity, otherwise no-ops. Gen guard per (domain, tuple)
  orders replay versus install; refused/unknown-domain handling mirrors the
  existing `ImportsRefusedByHelper`/`DeletesStaleIgnored` counters.
Mixed-version skew has the explicit two-direction rule: old→new bare applies with gen-guard-only semantics, so colliding pre-existing over/under behavior remains possible until both peers upgrade. New→old domain deletes are withheld, leaving stale A on the old peer; promotion during that in-window can resurrect A.


### 1.3 Failover traces (A deleted, B survives — both orderings)

Ordering 1 — delete before promotion. Primary helper holds A+B, mirror shows
B. Commit deletes A's policy. READ verb names (A, tuple) only (§3). Primary:
scoped helper delete of A + collision-aware mirror handling (§2). Go always
queues `QueueDelete(A, tuple, expected_rt_flow_session_id)` for the captured
match, even if the local helper reports `stale_forward`; the standby
conditionally deletes only its matching A RT_FLOW incarnation. Failover
promotes: B present on both nodes, A absent on both. Journal/replay: if the
peer was disconnected, the domain+RT_FLOW-identity delete journals and replays
on reconnect; the per-domain generation guard orders it against newer A
installs.

Ordering 2 — promotion before delete. Old standby (now primary) holds A+B as
synced+local rows; the policy-delete config arrives via config sync. New
primary runs the same READ verb against its helper, which MUST scan both local
and synced tables (unified view; the synced-side predicate is
`synced_session_contains`, sync_session.rs:261-272). Names (A, tuple) →
deletes locally → queues `QueueDelete(A, tuple,
expected_rt_flow_session_id)` to the new standby. Resurrect rule: promotion
never resurrects a `(domain, tuple)` delete whose generation tombstone orders
the install; the captured RT_FLOW id is equality-only, so a current row with a
different id is preserved by the conditional helper delete. The generation
tombstone is per scoped identity, same shape as the existing
delete-ahead-of-install guard in QueueDeleteV4's contract, sync_conn_write.go:
180-187; bulk-reconcile treats a missing (domain, tuple) on the owner as
authoritative-absent and must neither re-push it nor delete the survivor's row
(implement lane pins the reconcile seam; the invariant is normative here).

## 2. Mirror lifecycle (required block 2)

### 2.1 Verb return shape (READ verb, Q1)

`list_sessions_by_policy { policy_ids[], mode: prepublish|legacy,
before_secs?, families[], classes[] }`
returns `matches[] { addr_family, routing_domain, tuple, reverse_key,
policy_id, created_secs, created_ns, expected_rt_flow_session_id,
companion_policy_id, expected_companion_rt_flow_session_id }` +
`per_worker_errors[]` + `complete: bool`, chunked with a continuation cursor
(§4). `created_secs` (and optional `created_ns`) is returned for audit and the
legacy time fence; prepublish mode deliberately applies no `before_secs`
filter. The two expected RT_FLOW ids are the canonical conditional-delete
identities for the independently installed forward/reverse rows. They come
from Rust `SessionEntry.session_id`; Go's node-local
`dataplane.SessionValue.SessionID` is never used for HA identity. A zero
forward id is an `identity_missing` integrity failure; a zero companion id is
valid only when the forward has no reverse row. Any other missing/unknown
required id is `identity_missing`, not `stale_capture`, and never an
unconditional delete.
- Go retains each match as `SessionEntryV4/V6{Key: tuple, Value: {RoutingDomain,
  ReverseKey, PolicyID, Created}}` for counts/logging plus an identity sidecar
  `{expected_rt_flow_session_id, expected_companion_rt_flow_session_id,
  created_ns}`. It invokes a new `deletePolicyMatchesScoped` path from
  `deleteInvalidatedSessions`: send an explicit domain-scoped helper delete
  carrying both local expected row identities, collect applied/stale-forward/
  partial-companion outcomes, then issue the domain-carrying QueueDelete for
  every captured match (including a local stale-forward), carrying ONLY the
  expected forward RT_FLOW id; the peer conditionally derives its reverse.
  It MUST NOT call existing `DeleteBatchKnownV4/V6` for these matches, because
  that API begins with a bare mirror delete. Existing DeleteBatchKnown remains
  for non-verb paths. The policy-invalidation capture object holds matches +
  per_worker_errors + complete; non-nil + complete + 0 matches =
  positively-known-empty (§4).

- Forward rows ONLY: the scan skips `IsReverse != 0` (same rationale as the
  Go sweep comment at daemon_policy_invalidate.go:416-419 — a reverse row
  carries the same policy_id, so including it double-deletes, and for NAT
  targets the translated tuple). Go expands companions using the same rules as
  `DeleteBatchKnownV4/V6` (reviewer-verified companion expansion at
  session_store.go:555-563), but routes every forward and companion through
  `deletePolicyMatchesScoped`; it does not call that bare-mirror API here.
- `policy_id 0` is NEVER returned by the generic READ (server-side exclusion):
  the id-0 first policy stays owned by the helper `#9526` purge
  (`purge_sessions_bound_to_deleted_first_policy`, reviewer-verified
  `session_glue/mod.rs:680-742`), which discriminates by bound rule-handle,
  not by sweeping the overloaded zero value (host-inbound/fabric/tunnel/
  synced/legacy zeros + rolling-upgrade whole-table zeros,
  daemon_policy_invalidate.go:37-66).
- Every exact #9526 removal is nevertheless routed through the same tuple
  coordinator and collision-safe mirror repair as §2.2; because the purge
  currently runs on a worker with `&mut SessionTable`, it first reports
  candidates (forward/reverse keys, domains, independent
  `expected_rt_flow_session_id` values, and rule-handle) and returns to the
  worker command loop. The coordinator then initiates the conditional
  removals/probes (no worker self-deadlock); its close delta/HA peer delete
  carries only the forward expected RT_FLOW id, while the local reverse id is
  used only by local conditional removal. It never enumerates unrelated zero
  carriers, while a first-policy A colliding with B preserves B on helper,
  mirror, and standby.

### 2.2 Who mutates the bare row (helper owns it for verb-driven deletes)

- Existing Go `BatchDeleteSessionsScoped` (manager_sessions.go:560-566) deletes
  the mirror row BARE before/alongside helper IPC and is therefore NOT the
  policy-invalidation path after this fix. Its current contract remains for
  non-policy GC/operator/stale callers. The new `deletePolicyMatchesScoped`
  path sends the existing domain-present `sync_session` delete shape
  helper-first, then uses the applied result for the HA domain delete; it
  never issues a bare bpfShim delete. Precedent: #9714
  `deleteAppliedMirrorRows` (manager_sessions.go:613-639) makes mirror
  mutation follow helper-applied truth.

Rule (normative): for verb-driven deletes the HELPER owns mirror mutation,
because only the helper holds the survivor's value (Go cannot re-publish B
after a bare row delete — it has no B value once the row is gone).

- Shared tuple mutation sequence (load-bearing, R1 bounds): the helper owns a
  sharded gate keyed by bare `(addr_family, tuple)`: 256 shards (power of 2,
  `FxHash(family, tuple) % 256`), each a `Mutex<HashMap<TupleKey, Arc<GateEntry>>>`
  capped at 1024 entries (a full shard returns retryable `gate_table_full` and
  no BPF write). The shard mutex is held only for microsecond
  lookup/insert/remove. Each entry has `Idle/Publishing(n)/Draining/Held(token)/
  Finalizing/Aborting` state, atomic publisher count, and atomic install-permit
  count. A normal BPF publisher first acquires a `PublishPermit`, incrementing
  the publisher count; that permit remains held through the actual BPF
  publish/delete syscall and releases only afterward.
  Permit acquisition performs lookup, state validation, and counter increment
  while holding that shard mutex; idle removal rechecks `state=Idle` and both
  counts zero under the same mutex before deleting the map entry. A retained
  `Arc<GateEntry>` therefore cannot be removed and replaced for the same tuple
  while a permit exists; no ABA split can bypass serialization.
  Every worker-local `SessionTable` install/replace/remove calls non-blocking
  `try_acquire_install`; on success it increments `install_seq`, spans the
  complete table mutation, and releases afterward without holding a table lock
  or BPF permit. On `Draining`, `Finalizing`, or `Aborting`, denial defers
  that tuple's install to the worker's bounded retry slot (five polls/10ms),
  returns to command draining, and retries after release; it never synchronously
  blocks the worker that must process a survivor probe. A delete changes `Idle`
  to `Draining` (blocking new publish permits), waits for publisher count zero,
  then changes to `Held(token)`. Before the final survivor probe it changes
  `Held` to `Finalizing`, blocks new install and publish permits, and drains
  both active counts while workers continue their command loops; the
  probe→repair→release window therefore has no table mutation or BPF syscall
  racing it. Distinct tuples proceed in parallel, and idle entries are removed
  only after all permits release.
  A delete micro-batch holds at most 128 tuple entries: 64 forward keys plus
  at most one reverse-companion key per match. During `Draining`, transient
  publisher and install permits are each bounded by `128*W<=16384`, and both
  counts are zero before `Finalizing` probe/repair. The gate never grows with
  the full 262144-match capture.
- Every non-holder BPF publish path for that tuple (local admission, HA import,
  refresh, and #9526 purge) takes its `PublishPermit` before `publish`/`delete`.
  The policy-delete coordinator is the sole exception after `Held(token)`:
  its survivor repair calls token-authorized
  `publish_under_token(token)` or `delete_under_token(token)`, which validates
  the current `Held` or `Finalizing` token (or the coordinator-only repair
  token issued after quiescence) and performs the BPF syscall without acquiring
  a normal permit. Workers never write around the gate.
- Helper-first cross-process boundary (R1 correction): Go MUST NOT issue a
  session-map BPF mutation syscall. Replace every production
  `bpfShim.SetSession*`, `DeleteSession*`, and `BatchDeleteSessions*` mutation
  below with tuple verbs `mirror_upsert`, `mirror_publish_only`,
  `mirror_delete`, and `mirror_delete_batch`. Each tuple verb derives the
  complete forward-plus-reverse BPF key set, deduplicates it, acquires a
  bounded `GateLease` with per-key `TupleToken`s in canonical family/tuple
  order, and performs the `SessionTable` mutation plus every BPF
  publication/deletion under those tokens in the helper process. The response
  is sent only after table and mirror state agree; a reverse companion cannot
  publish outside the gate.
- `mirror_clear_chunk` is the deliberate map-wide exception: the helper owns
  cursor/page enumeration under a global clear fence, deletes both helper
  table and BPF rows in bounded chunks, and returns continuation, v4/v6
  counts, and first-error status. Go only drives that continuation; it never
  enumerates or deletes through the shim and never acquires an unbounded
  tuple-gate set.
- Clear-fence ordering is normative: every tuple mutation first takes shared
  `ClearAdmission`, then its `GateLease`/`PublishPermit`; `mirror_clear_chunk`
  transitions `Draining`, rejects new admissions, drains existing leases and
  permits, then takes exclusive `ClearFence` before bounded enumeration. The
  helper retains a `ClearFenceID` plus epoch across every continuation page;
  Go sends only the cursor/token and cannot release/reacquire the fence between
  pages. Each `ClearFenceID` has a bounded continuation-idle expiry; if Go
  stops sending pages, the helper aborts the clear, records an incomplete
  first-error, quiesces any active callback, and releases `ClearAdmission`. A
  retry starts a fresh clear epoch/cursor and cannot claim completion from the
  partial run. Draining/fence acquisition has a bounded deadline of one 200ms
  lease window plus a 50ms abort drain; expiry returns typed `clear_timeout`/
  first-error status, commits no page, and releases admission only after
  fenced abort quiescence. The order is never reversed: queued delete/import
  waits for clear release, while clear waits only for operations that already
  hold `ClearAdmission`; callbacks carry the exclusive token through
  table/mirror removal without reacquiring normal admission.

- Restart quarantine owns a helper-owned durable `ReconcileProbeStore`, keyed
  by logical mutation identity plus tuple/family, recording operation phase and
  `SessionTable` identity pre/post fingerprints. On restart, the helper
  rebuilds a `SessionTableIdentityIndex` from durable table/journal rows and
  emits a `ReconcileOrphanReport` for every BPF mirror row lacking an indexed
  identity; BPF is consulted only for pre-image/rollback and orphan accounting,
  never to classify `Applied`. `reconcile_quarantine` holds all mutators until
  probe-store replay, identity-index rebuild, orphan accounting, and bounded
  table reconciliation complete; every in-flight identity must resolve to
  `Applied`, `Noop`, or `Absent` from the store/index before the new epoch is
  published. Go reissues only after release with a new epoch-scoped operation
  id, and the helper consults the identity index/store before mutating so a
  different incarnation is preserved.

- Pre-dispatch `helper_unavailable` is fail-closed: no tuple BPF syscall has
  occurred. A lost or post-dispatch transport response is `unknown_outcome`;
  the helper may already have applied the transaction, so the caller waits for
  reconcile quarantine and reissues the same logical identity under a new
  epoch-scoped operation id. The existing Go best-effort mirror shortcut is
  removed; no direct shim fallback is permitted for local admission, HA import,
  policy delete, stale sweep, or clear.
- `SetSessionV4/V6` forwards and both forward
  `SetClusterSyncedSessionV4/V6` branches submit their values to
  `mirror_upsert`; helper-side synthesis covers the reverse companion. A
  reverse-only local or HA import is deliberately different: it uses a
  helper-gated `mirror_publish_only` operation for the exact reverse BPF key,
  which mutates no `SessionTable` row and is not the ordinary standalone
  reverse `sync_session` upsert that the helper refuses. The operation acquires
  the same key gate and publishes only the retained reverse mirror value.
- The #5305 transaction applies only to forward `mirror_upsert`: the helper
  snapshots the BPF pre-image and SessionTable row, applies the upsert and
  helper mirror publication, and rolls both back before returning a typed
  failure. `mirror_publish_only` has its own BPF pre-image/result and never
  creates a helper table row. Both requests carry a logical mutation identity
  plus `(helper_epoch, operation_id)`. A lost response is reported
  `unknown_outcome`, never success; after the helper reconciles, Go reissues
  with a new epoch-scoped operation id carrying the same logical identity; the
  helper probes the `SessionTableIdentityIndex` and `ReconcileProbeStore`
  first. An already-applied upsert returns `Applied` without rewriting a
  different incarnation; an absent upsert applies once; a conditional
  publish/delete already applied returns `Noop`. No unknown outcome triggers
  a direct Go repair write. `restoreBPFSessionV4/V6` becomes a
  token-authorized helper rollback, not a `bpfShim.SetSession`/`DeleteSession`
  call.

- Helper-backed `DeleteSessionV4/V6`, `DeletePeerSyncedSession`/V6,
  `BatchDeletePeerSyncedSessionsScoped`/V6, scoped/bare batches, and
  `deleteAppliedMirrorRows` use `mirror_delete*` and receive
  `preserve`/`delete`/`republish` dispositions. The helper performs the sole
  final mirror mutation under matching per-key tokens; Go suppresses all
  post-repair bare deletes. Scoped-batch wrappers retain #10513's
  `surfaceScopedHelperDeleteError`/Join/precedence boundary, while legacy
  non-policy callers retain bounded chunk and count/error contracts. All use
  helper-first mutation. `ClearAllSessionsChunked` becomes bounded
  `mirror_clear_chunk` calls under one helper-owned `ClearFenceID` across all
  continuation pages, so no tuple publisher can bypass the fence.

- Post-#10513 source audit enumerates every current production direct
  session-map mutation in `manager_sessions.go` (21 callsites, including
  clear): `SetSessionV4:37`; `SetClusterSyncedSessionV4` reverse/forward
  `107/132` and rollback `189/194`; `SetSessionV6:201`;
  `SetClusterSyncedSessionV6` reverse/forward `236/248` and rollback
  `283/288`; `DeleteSession:346`; `DeleteSessionV6:425`;
  `DeletePeerSyncedSession:493`; `DeletePeerSyncedSessionV6:508`;
  `BatchDeleteSessions:537`; `BatchDeleteSessionsScoped:563`;
  `BatchDeleteSessionsScopedV6:590`; peer-batch applied-row closures
  `643/653`; `BatchDeleteSessionsV6:704`; and the direct
  `bpfShim.ClearAllSessionsChunked` call at `769` (wrapper
  `ClearAllSessions:743`, maps implementation `maps_session.go:450`).
  Compared with the pre-#10513 audit, scoped-batch anchors moved
  `561/570`→`563/590`, peer closures `598/608`→`643/653`, the V6 bare batch
  at `704` is explicit, and clear moved from the old wrapper pin to the
  direct callback call. Every listed callsite becomes an RPC wrapper, not a
  Go BPF write. `LegacyDataPlaneAdapter` delegates to these methods and adds
  no direct shim writer; read-only `GetSession` and fixture seed calls remain
  out of publisher scope.
- Lock order is normative: Go does not hold `m.mu` while waiting for helper
  gate admission or a BPF operation. The helper acquires its `GateLease`,
  mutates `SessionTable` and BPF, and returns a typed result; Go then takes
  `m.mu` only to record the result/health state. No helper worker waits for
  `m.mu`, and no Go path can resume a stale direct syscall after helper
  restart. A helper crash/restart bumps the coordinator epoch and rejects
  old `(helper_epoch, operation_id)` pairs until map reconcile completes.
  Go receives `unknown_outcome`, then submits a new operation id carrying the
  same logical identity; the reconciled helper consults the
  `SessionTableIdentityIndex`/probe record and returns `Applied`/`Noop` if
  the old transaction had completed, or applies it once if absent, with
  conditional identity checks preserving any different incarnation. Thus
  #5305 cannot split on a lost response and helper restart cannot admit a
  stale direct writer.

- Install-generation revalidation: each worker-local table mutation uses the
  non-blocking `InstallPermit` protocol above and returns the observed
  `install_seq` with its survivor probe. Before the final probe the coordinator
  switches `Held` to `Finalizing`; new installs receive bounded deferral and
  keep draining commands, while the coordinator waits at most 20ms for the
  active install count to reach zero. It then performs the final
  probe→token-authorized repair while no table mutation can begin; a changed
  sequence during earlier repair passes forces another pass, up to three
  passes or the remaining 200ms lease. A continuously changing tuple stays
  fenced and returns `gate_timeout` rather than releasing with a mirror gap.
- Token and lease: each tuple key has
  `TupleToken { seq: u64 per-shard monotonic, shard: u8 }`, while every
  tuple-scoped helper mutation obtains one `GateLease { epoch: u32
  coordinator epoch (bumped on restart/reconcile), expiry_ns: u64 monotonic,
  entries: Vec<(TupleKey, TupleToken)> }`. `mirror_clear_chunk` is the
  map-wide exception: it owns the exclusive `ClearFenceID`/epoch above across
  its full continuation and never uses a tuple `GateLease`. The full
  forward-plus-companion key set is derived and deduplicated before any
  acquire; entries are sorted in
  canonical family/tuple order, acquired as one bounded operation, and
  released together. Helper operations validate the token corresponding to
  each BPF key plus the shared lease epoch/expiry; a singular per-shard token
  can never authorize a different shard. Gate acquisition is separate from
  the sequence lease: the batch may spend at most 100ms trying to acquire the
  sorted key set; a `Draining` entry waits at most 20ms for existing
  `PublishPermit`s to release. Only after every publisher count reaches zero
  does each entry become `Held` and set its 200ms expiry. Workers accept only
  exact key-token+epoch with `now < expiry`, else `TokenStale`; the coordinator
  accepts only acks carrying the issued `GateLease`. No Go process performs a
  BPF syscall under this lease, so expiry cannot leave a paused direct writer
  behind; expiry instead fences the helper lease before recovery. A
  continuously changing key set stays fenced and returns `gate_timeout` rather
  than releasing with a mirror gap.
- Command queues: each delete micro-batch is represented by three batched
  `WorkerCommand` envelopes (`conditional_probe`, `conditional_remove`, and
  survivor probe), each carrying at most 64 `(GateLeaseID, match)` items.
  The referenced lease carries the canonical key→token set; workers validate
  the token for every forward/companion BPF key they touch. Envelopes use the
  existing per-worker `Mutex<VecDeque<WorkerCommand>>` via `push_bounded` ONLY
  (`MAX_PENDING_WORKER_COMMANDS=4096`,
  `WORKER_COMMAND_DRAIN_BUDGET=256`, worker_queue.rs:80,580). Kick is
  non-blocking; a refused push, poisoned mutex (`lock_recover`, committed
  prefix kept), or dead-worker shed maps to a named `per_worker_error` for
  that batch, never a silent drop. Workers drain at most 256 command
  envelopes per pass and feed `commands_backlogged` into `did_work`; the
  delete handler separately caps 64 matches per phase/pass and yields before
  the next AF_XDP poll. This is a tuple/work bound, not a timing
  extrapolation from the full-queue benchmark; implementation must measure
  the real BPF syscall budget. A micro-batch therefore has at most 192
  command-match slots per worker across its three phases and at most 128
  BPF gate entries coordinator-wide, with bounded ring stall.
- Refresh integration: `refresh_bpf_conntrack_last_seen(..., sessions:
  &SessionTable, ...)` (bpf_map/mod.rs:1035-1039) keeps `&SessionTable` (no
  `&mut`, no table lock) and gains `gate: &TupleGate`. Each budgeted cursor
  tuple calls `gate.try_acquire_publish(tuple)`; the returned
  `PublishPermit` is held through the `BPF_EXIST` refresh syscall and then
  released. When the tuple is `Draining`, `Held`, `Finalizing`, or `Aborting`,
  the refresh
  skips this pass and retries on the next cursor wrap. Installs, HA imports,
  and refresh all acquire the same permit before the BPF syscall; an install
  may update its worker-local table first, but its BPF publish defers for up
  to five worker polls (at most 10ms), so the survivor probe sees it while
  no write can bypass the gate. Persistent contention returns retryable
  `GateContention`/`gate_table_full`, never a drop.
- Liveness: on phase timeout, worker panic, quarantine, death, or an HA-import
  race, the coordinator marks the `GateLease` `Aborting` and blocks new
  `PublishPermit`s for every key in its key→token set. It first drains live
  worker acks for at most 50ms; it does not repair yet. On a confirmed-dead
  worker, it takes that worker's queue lock and filters each batched envelope
  in place, removing only items whose `(GateLeaseID, match)` equals this
  abort; it preserves item order and unrelated lease items, dropping an
  envelope only when it becomes empty. It then marks the worker
  fenced/non-executable for this epoch; dead queues are not required to become
  empty. A resurrected worker gets a new coordinator epoch, so stale commands
  cannot execute. A helper crash also invalidates every in-memory lease and
  mutator RPC; restart enters reconcile quarantine and publishes a new epoch
  before accepting any mutation, so no paused Go caller can issue a direct BPF
  syscall. The lease remains `Aborting` until all live-worker acks/queue
  entries are quiescent. If the internal lease expires first, the coordinator
  issues a fresh probe-only recovery lease accepted by live workers for
  survivor reads only (no remove, publish, or permit acquisition), collects
  those bounded acks, then issues a coordinator-only repair token. After
  quiescence, it runs that final survivor probe and performs the
  token-authorized repair (republish B or delete the bare row) for the matching
  key tokens, then releases the lease. If final probe/repair cannot complete,
  it retains the fence and returns visible `gate_timeout` or
  `per_worker_error`, never an unlocked repair or an early optional repair.
  Shed queues (`worker_command_queue_shed_total`), poison recoveries, and
  drops (`worker_command_queue_drops_total`) all force batch `complete=false`
  (R2).
- Necessity: conditional-delete plus republish without BPF serialization loses
  when delete probes (no survivor), concurrent B installs into its table and
  publishes the bare BPF row, then delete deletes that fresh row. The gate
  serializes BPF mutations only: a publisher holds its `PublishPermit` through
  the syscall, while table installs stay worker-local. A concurrent install's
  BPF publish waits, so the second survivor probe (which reads `SessionTable`,
  not BPF) sees B and the repair republishes B instead of deleting.
- Proof sketch: under the tuple gate,
  `probe, conditional_remove, survivor-probe,
  publish_under_token/delete_under_token` is atomic with respect to every
  helper-internal tuple publisher, including `mirror_upsert`,
  `mirror_publish_only`, refresh, and HA import; clear is the explicit
  map-wide exception and owns exclusive `ClearFence` through its full
  continuation. Non-clear tuple operations hold their per-key
  `PublishPermit` through each BPF syscall; clear callbacks use only their
  `ClearFenceID`, and no tuple publisher can enter until its release. Go
  callers can only enqueue these helper verbs and have no direct map syscall
  that could bypass `Held`, `Finalizing`, or `ClearFence`. Conditional ids make
  removal equality-only (stale or different ids are no-ops, so tuple reuse
  cannot over-clear); survivor selection is deterministic over post-remove
  table contents (which include every concurrent install); each worker's
  `install_seq` is compared after token-authorized BPF repair, and any change
  forces another probe/repair before finalization. The repair (`BPF_ANY`
  republish when a survivor exists, else bare-row delete) validates the Held
  or Finalizing sequence token (or coordinator-only repair token) and
  happens before release with no unobserved install. Hence section 2.3 items
  (1)-(4) follow: helper holds B, mirror carries live B, `ForEach` enumerates
  B, no phantom A. Abort preserves safety via fence→quiesce→final
  probe→repair or visible failure; it never releases an early silent partial.
- The domain-present helper delete path used by `deletePolicyMatchesScoped`
  is collision-aware and identity-conditional. It probes each independently
  installed half under the sequence token. A missing/different forward
  `expected_rt_flow_session_id` is a `stale_forward` no-op; a matching
  forward is removed. An absent expected companion is an idempotent no-op; a
  matching `expected_companion_rt_flow_session_id` is removed; a different
  companion is preserved and reported as `partial_companion`. Any applied
  half triggers the survivor probe across every worker and mirror repair.
  Go always queues the forward-id conditional HA delete; the peer derives its
  own reverse companion after that forward matches. If B exists, re-publish its
  row (`publish_bpf_conntrack_entry`, `BPF_ANY` recreate) with its value
  (domain, policy_id, reverse key); else delete the bare row. Reverse
  companion follows the forward's domain (existing #9146/#9364 scoping).
- Refresh/reconcile writes remain `BPF_EXIST` and therefore cannot recreate a
  missing row; only the tuple sequence's validated survivor repair may use
  `BPF_ANY`. Go MUST NOT issue a bare `bpfShim` delete or publish during the
  sequence (it would destroy/race B's row). The #9526 purge uses this same
  sequence without sweeping unrelated zero carriers.

### 2.3 B-visibility-preservation proof (asserted by cells in §5)

After deleting A on a colliding tuple, the tuple sequence has quiesced every
worker publisher for the whole repair: (1) helper holds B (scoped delete named
A only; B never matched); (2) the mirror row EXISTS and carries B's value
(re-published by the collision-aware delete; if the row already carried B, the
helper leaves-or-rewrites B — invariant: a tuple with any live session has a
row carrying a LIVE tenant's value); (3) `show`/GC/sweep/bulk/stale consumers
(`ForEachV4/V6` → `BatchIterateSessions`) enumerate B with B's PolicyID +
RoutingDomain; (4) no phantom A targeting (A's value is gone from mirror and
helper). If instead the row carried A's value at delete time (A was last
publisher), the same sequence replaces it with B's republish, never leaves
stale A (which would linger to GC expiry and phantom-retarget future sweeps).

### 2.4 Delete-phase fan-out and completion (R2)

- Candidate batching: a complete READ yields at most
  `MAX_CAPTURE_MATCHES=262144` identities. Go retains them in bounded
  4096-entry candidate pages and sends sequential delete micro-batches of at
  most 64 forward matches and at most 128 deduplicated BPF gate keys (the
  forward key plus a possible reverse companion for each match). Go
  pre-expands captured reverse keys where present; the helper validates that
  set and derives only a missing companion during a preflight. If preflight
  would exceed 128, it rejects before gate acquisition and Go splits the
  forward page. The helper then acquires all keys in canonical
  `(addr_family, tuple)` order; only after the `GateLease` is held does it
  order conditional work by
  `(routing_domain, expected_rt_flow_session_id,
  expected_companion_rt_flow_session_id)`. Thus the worst case is 4096
  micro-batches, never one unbounded `262144 × W` broadcast. A micro-batch
  runs the three phases, performs the final token-authorized survivor repair,
  then releases all gates before the next micro-batch.
- Kick/collect: delete uses the same control-handle discipline as READ:
  validate and kick while locked, unlock, collect lock-free, then attach
  status. The delete handle has a separate 30s absolute deadline from its
  first kick. Each micro-batch has the R1 100ms acquire budget and 200ms
  sequence lease, with 20ms per-phase collection. The coordinator stops
  issuing new micro-batches at `deadline-300ms`, reserving the worst
  acquire/lease/abort/final-repair envelope for the active batch; every active
  batch must finish or enter the fenced abort state by the absolute deadline.
  At the deadline it reports `complete=false` and never waits indefinitely or
  queues work after the gate fence. The outer commit keeps `d.applySem` until
  clear returns; this separate delete deadline bounds that additional hold to
  30s, while any fenced token cleanup continues without normal/unfenced BPF
  writes; only the token-authorized final repair may run.
- Worker fan-out: each micro-batch sends three batched
  `WorkerCommand` envelopes to each live worker, each envelope carrying at
  most 64 token/match items. For `W<=128`, that is at most 384 queue pushes
  and 192 command-match slots per worker per micro-batch; the coordinator's
  separate `GateLease` cardinality is at most 128 BPF keys. Each worker's
  `MAX_PENDING_WORKER_COMMANDS=4096` queue and 64-match-per-phase drain
  budget remain the hard limits. A refused push, queue poison, dead-worker
  shed, token expiry, gate-table full, or per-phase ack shortfall records a
  named `per_worker_error` and terminates that micro-batch safely; no command
  is silently discarded.
- Completion: a micro-batch is complete only after every live worker has
  acknowledged probe/remove/survivor phases and the final repair has run (or
  every conditional operation was an explicit stale/no-op). The overall
  delete result is `{batches_applied, batches_noop, per_worker_errors,
  complete}`; `complete=true` requires every candidate micro-batch to reach a
  terminal result with no queue, gate, worker, or deadline error. A stale
  forward remains a successful local no-op and still queues the conditional
  HA delete; a partial companion remains visible and queues the forward HA
  delete.
- Partial mapping and retry: `gate_timeout`, `gate_table_full`,
  `queue_overflow`, `token_stale`, `worker_dead`, `per_worker_error`,
  transport failure, or delete deadline produces `complete=false` plus
  `clearErr` joined into #5578 (config remains committed+active, success line
  suppressed, safe fan-out for matches-in-hand still attempted). Helper abort
  follows §2.2's fence→quiesce→final-probe→repair order; it never falls back
  to a bare or unconditional mirror delete. Retry is scoped to re-issuing an
  unfinished micro-batch within this commit, reusing its captured
  domain/tuple/forward and companion RT_FLOW identities; after `clearErr` is
  returned, the capture is consumed and dropped, with no cross-commit
  retention. Applied and stale batches remain idempotent, and the peer still
  receives only the forward identity and derives its local reverse.
- AMENDMENT (2026-09-22, preflight deletion — architect-approved): the
  implementation runs TWO worker envelopes per micro-batch (conditional
  remove, survivor probe), not the three above. Each of preflight's plan
  roles is vacuous, and lease-gating by preflight would be actively harmful:
  1. Derive-missing-companion: Go always pre-expands (validated: a nonzero
     expected companion identity requires a captured reverse tuple), so the
     helper REFUSES a missing capture fail-closed instead of deriving one.
     No sender omits; a derivation path would be dead code.
  2. 128-key cap gate: enforced at entry from the captured tuples without
     any fan-out; over-cap rejects before acquisition exactly as specified.
  3. Lease-gating short-circuit (skip the lease when nothing appears to
     proceed): REJECTED on soundness. Any check-then-skip races a concurrent
     same-incarnation re-import (lagged peer sync) landing between the check
     and the skip: the batch would skip what it should remove and count the
     survivor stale — under-clear by TOCTOU. The implementation leases ALL of
     every batch's keys uniformly instead: a lease failure then aborts with
     provably zero mutations (nothing before acquisition mutates), and no
     short-circuit TOCTOU can arise. Brief over-fencing of stale tuples
     (retransmit-healed) is the accepted cost.
  Validation preflight would have provided happens instead at execution,
  atomically with respect to each worker's single-threaded table (the
  check-then-teardown observes identical state: no other thread can name
  those entries, and OS preemption freezes the table rather than interleaving
  foreign mutations): the forward incarnation is re-checked, the companion is
  re-derived from the live forward's NAT and compared for full key equality
  with the capture, and any mismatch preserves (partial) rather than deleting
  by an uncertain key. Preflight evidence would be strictly staler — a
  replacement landing between preflight and removal flips its verdict — so
  execution-time evidence supersedes it wherever the two could disagree.
  Pinned by `policy_batch_lease_covers_forward_key_10512` and
  `policy_batch_lease_covers_companion_key_10512` (each leased key blocks the
  batch when pre-held, with shared authority provably intact on refusal) and
  `policy_batch_lease_ignores_unrelated_tuple_10512` (exact coverage: an
  unrelated held tuple never blocks). If review finds a live preflight role
  this analysis misses, restore the envelope rather than extending this note.
- AMENDMENT (2026-09-22, tree-consistent timing — architect-approved): the
  implementation keeps the tree's established fan-out discipline instead of
  the 20ms-phase / 200ms-sequence-lease / token_expiry-token_stale contract
  in Kick/collect above, element by element. The 100ms acquire budget and
  the 30s delete deadline are kept exactly as specified.
  1. 20ms per-phase collection → 250ms bounded fan-outs (the READ, export,
     and counters paths' established convention). A 20ms budget aborts on
     ORDINARY scheduler jitter (10–100ms deschedules are common on shared
     cores; 250ms stalls are rare), which would fail batches — loudly but
     spuriously — under routine load and force operator touching-recommits
     for timing noise. 250ms keeps spurious aborts rare; every abort still
     fails closed (complete=false joined into #5578).
  2. 200ms sequence lease → wait-bounded holds with no independent lease
     clock. Typical holds are milliseconds (same order as the existing
     shared-path deletes); only pathological multi-stall batches approach
     ~750ms versus 200ms. Same-tuple installs during a hold are refused and
     retransmit-heal; same-tuple deletes fail fast on the unchanged 100ms
     acquire budget — the longer bound costs latency-to-error, never
     correctness. True async expiry (freeing the gate under a live-but-
     stalled holder plus token refusal of its late repair) cannot help the
     case it targets — the holder is the single session thread, so a truly
     wedged holder already wedges session sync regardless of gate state —
     and is a gate-wide project, explicitly deferred, not silently dropped.
  3. token_expiry/token_stale errors + sequence validation → omitted as
     vacuous; lease COVERAGE is verified mechanically instead. Gate entries
     cannot be removed or re-claimed while held or permitted
     (`remove_if_idle` requires map-identity plus Idle plus zero counts
     under the shard lock; claims are denied outside Idle/Publishing), so no
     ABA can invalidate a held lease and a stored sequence cannot disagree
     with a live entry — validation would check for an impossible event.
     What `GateLease::covers` checks at every repair is the load-bearing
     half: a probe set that ever names an unleased tuple fails the batch
     loud instead of repairing unfenced (programmer-error backstop).
  Empirical leg: every Finalizing hold is observed
  (`xpf_userspace_policy_batch_{count,hold_ns_total,hold_max_ns}`);
  average hold must read ms-typical in production. If review or operations
  finds timing affects CORRECTNESS rather than latency-to-error, this ruling
  reopens.

## 3. Predicate + timing (required block 3)

- Frozen value: the verb scans `SessionMetadata.policy_id`
  (userspace-dp/src/session/entry.rs:241 — stamped at install). It is frozen
  because refresh takes `&SessionTable` (immutable, bpf_map/mod.rs:1035-1039)
  and re-stamps ONLY the BPF map value (:1091-1094) via
  `reresolve_session_policy_id` (policy.rs:1801-1819: bound+deleted →
  `DEFAULT_POLICY_SENTINEL_ID` (u32::MAX), unbound → frozen stamped). The
  bound handle (entry.rs:308) is IGNORED for matching (it exists for the
  #9526 discriminator and hit-count stability). Synced entries carry the wire
  scalar (entry.rs:303-305, frozen-at-sync); known residual: after an origin
  reorder the scalar may be stale (documented P2 #3322 follow-up) — the
  standby scan uses the same scalar, consistent with the origin's OLD
  numbering at sync time; noted, not solved here.
- Go OLD ids: `deletedPolicyRuntimeIDs` (daemon_policy_invalidate.go:93-118,
  id-0 excluded), `changedPolicyRuntimeIDs` (:631-651 + reviewer-verified
  remainder), `defaultPolicyChangeRuntimeIDs` (reviewer-verified :295-307)
  are computed at arm from (oldCfg, newCfg) exactly as today. Prepublish
  capture sends `mode=prepublish` with no `before_secs`: the helper scans every
  frozen OLD-id row encountered by each bounded worker cursor and returns
  `created_secs`/identity fields for audit. It MUST NOT use
  `d.policyActivationSecs` as a cutoff, because that value is stamped before a
  potentially long READ and would exclude OLD-policy admissions made while the
  READ runs.
- Legacy post-apply enumeration sends `mode=legacy` and
  `before_secs = d.policyActivationSecs`, captured by
  `daemonMonotonicSeconds` immediately before apply (`daemon.go:658-685`,
  `daemon_apply.go:515`). This is CLOCK_MONOTONIC seconds, matching the
  helper's `monotonic_nanos()/1_000_000_000` (`bpf_map/mod.rs:860`), not wall
  time; only this post-publish legacy mode applies the `created_secs` fence.
- Placement (two RPCs; #6948 preserved): (a) pre-publish READ RPC inside
  `capturePolicyInvalidationLocked`
  (daemon_policy_invalidate_capture.go:149-246, called at the last statement
  before `rt.ApplyConfig` from daemon_apply_dataplane.go:171) — a READ, so it
  cannot re-admit (capture.go:53-59); every session later deleted was OBSERVED
- Post-publish admission exclusion applies to legacy mode: it filters
  `created_secs <= before_secs` (helper-side analogue of the legacy
  `admittedAfterActivation := created > activationSecs`,
  daemon_policy_invalidate.go:444-447 — strictly-greater, ambiguous still
  cleared = over fail-safe, same ≤1s granularity residual). Prepublish mode
  deliberately has no stale `activationSecs` cutoff; rows admitted while its
  worker cursor runs are the acknowledged capture→publish residual, while
  exact RT_FLOW identities prevent later tuple reuse from being removed.
- Exact capture identity closes the remaining TOCTOU: local post-apply delete
  carries `expected_rt_flow_session_id` and independent
  `expected_companion_rt_flow_session_id`; worker commands condition each half
  separately while the tuple gate is held. A matching forward is removed; a
  missing/different forward is a `stale_forward` no-op. A matching companion
  is removed; an absent old companion is an idempotent no-op, while a
  different companion is preserved and reported as `partial_companion` (the
  safe forward removal still proceeds). `created_ns` remains a timestamp/fence
  value, never the identity. The HA wire carries ONLY the forward
  `expected_rt_flow_session_id`: once the peer forward matches, standby derives
  and removes its peer-local reverse (whose id is intentionally different).
  Local stale/partial outcomes never suppress that conditional HA delete.
  Thus capture→expiry→same-tuple replacement→delete cannot remove the
  replacement locally or on the peer.
- `policyInvalidationCapture` authoritative-empty invariant kept
  (capture.go:103-112 — non-nil + complete + empty means "ran, nothing to
  invalidate", distinct from nil "no capture taken"): the capture object holds
  verb matches + `complete`; consumed once
  (daemon_policy_invalidate.go:361-369).
- Legacy path (capture nil: boot, non-commit applies): SAME verb, with id sets
  from the legacy derivation and `before_secs = d.policyActivationSecs` (the
  existing pre-apply monotonic fence, never `now`; zero retains the existing
  no-fence behavior). Policy invalidations NEVER enumerate the mirror after
  this fix — the mirror scan remains ONLY for non-policy sweeps (GC/stale/show).
  Assumption (stated): userspace dataplane. If a legacy caller has no helper
  access, it fails closed with a #5578 error, never a silent mirror scan.
  Implement lane proves or narrows this assumption against the kernel-BPF path.
- Capture→publish residual: prepublish mode has no snapshot/time fence. A worker
  can admit an OLD-policy session after its cursor passes; it is not in
  `matches` and can forward until idle timeout. The bounded residual lasts at
  most the remaining READ deadline (30s overall) plus the actual `ApplyConfig`
  publish latency, not merely the call itself. This widened but explicit
  window is the security tradeoff for capturing admissions made during the
  scan; exact RT_FLOW identities still prevent later tuple reuse over-clear.

## 4. Fan-out bounds + failure mapping (required block 4)

- Bounds (Q3 closed): let `W` be configured live workers, hard-capped at 128
  worker ids (the existing `MAX_NAT_HOLDER_WORKERS=128` ceiling,
  userspace-dp/src/afxdp/bpf_map/steering_owners.rs:25-27). Each worker
  scans only its owner-local table: `W * DEFAULT_MAX_SESSIONS` rows = 64
  internal 2048-row chunks/worker. The shared synced authority is scanned once
  by the helper coordinator, not once per worker: its
  `2 * W * DEFAULT_MAX_SESSIONS` entry cap is `128 * W` internal chunks. The
  dedupe key is `(addr_family, routing_domain, tuple,
  expected_rt_flow_session_id)`; reverse rows are not returned. Thus the
  global internal bound is `192 * W` chunks, at most 24576 chunks for W=128,
  with no hidden W² fan-out.
- Wire paging is separate from scan chunks: a server-side capture handle/stream
  emits continuation pages of at most 65536 matches and 48 MiB encoded bytes
  (below the 64MB `MAX_CONTROL_REQUEST_BYTES`, protocol/control.rs:311). Go
  retains at most `MAX_CAPTURE_MATCHES=262144` candidates (four pages) across
  both families/classes; aggregate overflow returns `complete=false` rather
  than allocating unbounded memory. Every continuation uses the same 30s
  overall deadline from kick; the helper enforces a 100ms internal chunk
  budget. Exceeding the 192W chunk bound, 65536-match/48MiB page bound,
  262144-match capture bound, or 30s deadline returns `complete=false` with a
  named `per_worker_error`, `capture_limit`, or timeout, never an authoritative
  empty. The commit
  holds `d.applySem` during READ (daemon_policy_invalidate.go:146-147), so the
  30s maximum is a deliberate apply-window/security tradeoff, not an
  unbounded continuation loop.
- Lock discipline (Q3 closed): NEVER hold `ServerState` across the scan.
  Control-socket verb (the session socket serves EXACTLY
  ping/sync_session/session-update_ha_state; anything else is refused fast,
  handlers/mod.rs:233-249). Locked phase = validate + broadcast kick +
  capture wait handle (cf. `session_counters::kick`, handlers/mod.rs:452-460;
  export kicks :439-450); unlock; lock-free collect with timeout (cf.
  :513-517); status attach after (:473-481). The READ is diagnostic-shaped
  (like `session_counters`) despite its commit-path caller.
- Failure → #5578 mapping (normative table):

  | Outcome | Meaning | Commit result |
  |---|---|---|
  | complete=true, 0 matches | positively-known-empty | nil; success line allowed |
  | complete=true, N matches | full candidate set | delete N via §1+§2; join per-match errors |
  | complete=true, N matches with local `stale_forward` | captured forward
  already expired/replaced locally | local no-op is success; conditional HA
  delete still sent, and a peer copy with the captured id may be removed |
  | `partial_companion` (forward matched, companion id differed) | safe forward
  removed, replacement companion preserved | `clearErr` joined (visible
  partial outcome); conditional HA forward delete still sent |
  | delete `complete=false` / `gate_timeout` / `queue_overflow` /
  `worker_dead` / `token_stale` / `delete_deadline` | some candidate batches
  applied or no-op, but delete fan-out is not complete | `clearErr` joined into
  #5578; config remains committed+active, success line suppressed. Before
  returning `clearErr`, only unfinished micro-batches may be re-issued within
  this commit using the live capture; after `clearErr` the capture is
  consumed/dropped. A revert-and-re-apply of the policy change (or any commit
  whose diff re-covers the affected policies) re-runs invalidation and
  converges; a no-op re-commit returns clean WITHOUT re-targeting; until then
  explicitly clear the affected policies' sessions or allow idle expiry; never
  claim convergence or use a bare fallback |
  | `identity_missing` / `complete=false` / `per_worker_errors` / timeout /
  transport error / `unknown_outcome` / `helper_restart` / unknown-verb (old
  helper, handlers/mod.rs:468-471) |
  discovery or protocol integrity NOT positively complete | `clearErr` joined
  into commit (mark-and-continue: config stays committed+active, peer still
  syncs, operator sees failure; revert-and-re-apply the policy change (or any
  commit whose diff re-covers the affected policies) re-runs invalidation and
  converges; a no-op re-commit returns clean WITHOUT re-targeting; until then
  explicitly clear the affected policies' sessions or allow idle expiry —
  daemon_apply_commit.go:310-351); success line SUPPRESSED; safe fan-out STILL
  attempted for matches-in-hand; NEVER use an unconditional delete |
- NO mirror fallback (Q4 closed): unknown-verb/partial NEVER degrades to a
  PolicyID-only mirror scan — that reintroduces the silent miss. Old helper +
  new verb maps to `clearErr`, never nil.
- #10513 scoped-batch error contract remains normative after helper-first
  cutover: `BatchDeleteSessionsScoped`/`V6` maps typed `mirror_delete_batch`
  failures through `surfaceScopedHelperDeleteError`; helper failure wins over
  mirror `ErrKeyNotExist`, and a genuine mirror error joins it. The wrapper
  keeps `errSessionHelperUnreachable` discoverable without unwrapping dial
  `ENOENT`, so session-store per-key NotFound retry cannot swallow helper
  failure. `BatchDeleteSessions`/`V6` remain #5096 best-effort, peer-marked
  batches retain #9714 refused/applied semantics, and clear retains first-error
  propagation (#5881). `TupleGate` typed `Applied`/`Noop` is allowed only for
  conditional absence/already-completed identity; refusal, transport, and
  `unknown_outcome` stay surfaced and cannot be converted to `Noop`.
- Version floor: bump 30→31 on the merits (verified current floor:
  `ProtocolVersion = 30`, protocol.go:335; mirror
  `CONFIG_SNAPSHOT_PROTOCOL_VERSION = 30`, control.rs:197; exact-equality
  gates refuse cross-version snapshots outright, protocol.go:10-15). Pin the
  digest cell (`snapshot_shape_version_8892_test`). The cluster-sync delete
  widening (§1) needs its own MinProtocol gate + withhold rules. Rolling
  upgrade: new daemon + old helper → commit error with operator guidance
  until the helper upgrades (fail closed, visible).
- Operator guidance (draft; implement lane finalizes wording + docs):
  `policy session invalidation: helper session query incomplete or
  unsupported (need helper protocol >= 31); some sessions of <changed
  policies> may keep forwarding under stale authorization; complete the helper
  upgrade and revert-and-re-apply the policy change (or any commit whose diff
  re-covers the affected policies) so invalidation runs again; a no-op
  re-commit returns clean WITHOUT re-targeting; until then explicitly clear
  the affected policies' sessions or allow idle expiry.`
- Retry/idempotency: prepublish READ is idempotent with no time cutoff;
  legacy retries reuse the SAME `before_secs` to preserve its capture fence.
  Deletes are idempotent by `(domain, tuple,
  expected_rt_flow_session_id[, expected_companion_rt_flow_session_id])` on
  the local helper; an absent/different incarnation is a conditional no-op,
  while a matching incarnation is removed once. Only unfinished micro-batches
  may be re-issued within the current commit; after `clearErr` the capture is
  consumed/dropped and no cross-commit identity retention is allowed. The peer
  uses only the forward RT_FLOW identity and derives its local reverse, so
  within-commit retries converge without a bare delete (per-key NotFound
  contract owned by #10528).
- Helper-first restart retry: `mirror_upsert`/`mirror_publish_only`/
  `mirror_delete*` responses are typed `Applied`, `Noop`, `Stale`, or
  `unknown_outcome`. After `unknown_outcome` or `helper_restart`, the Go
  caller waits for reconcile and reissues the same logical identity under a
  new `(helper_epoch, operation_id)`; the helper probes before mutating.
  A matching prior upsert is `Applied`, an absent one applies once, and a
  conditional delete/publish already completed is `Noop`. No cross-epoch
  bare write or unconditional rollback is allowed.

## 5. Tests (required block 5)

Privileged collision cells (all THREE classes × both families × both
producers + failover; each states its failing defect on base: A survives,
commit nil, via the PolicyID-only predicates at
daemon_policy_invalidate.go:449-477 + capture.go:210-237 vs survivor B id →
`c.empty()→nil` at daemon_policy_invalidate.go:529-532):
Matrix rule: every class/family combination runs once through the capture
producer and once through the legacy producer. T1–T4 name the deleted-policy
cells explicitly; T5–T7 repeat each listed family/class assertion in both
producer modes rather than relying on the deleted-policy rows as proxies.

- T1 deleted/v4/capture, T2 deleted/v6/capture, T3 deleted/v4/legacy,
  T4 deleted/v6/legacy: install A(100007)+B(100008) same tuple → commit
  deleting A's policy only → A gone (helper + mirror + standby), B intact
  (helper + mirror + standby), commit error nil iff discovery complete.
- T5 modified/v4+v6/capture+legacy: same collision, A's policy
  match/action changed with `policy-rematch` set → A's sessions reaped, B
  untouched. (Same shadow: all three classes share the predicate via the
  three-way switch at capture.go:214-220 and the joined clears at
  daemon_policy_invalidate.go:360-379.)
- T6 modified scheduler-flip (#4343)/v4+v6/capture+legacy: A's scheduler
  active→inactive → same assertions.
- T7 default/v4+v6/capture+legacy (#4342, `DefaultPolicySentinelID` =
  u32::MAX): default permit→deny with colliding default-permit sessions →
  same assertions.
- T8 failover both orderings (§1.3) for deleted/v4 + v6 spot: delete-before-
  promotion AND promotion-before-delete; assert no A resurrection, no B loss.

Unprivileged verb-coherent cells (ordinary CI): fake helper speaking
`list_sessions_by_policy` (per-domain table, frozen ids, prepublish no-cutoff
mode, legacy `Created <= before_secs` fence, RT_FLOW identity checks, chunking,
error injection) + recording Go manager; drive arm→READ→clear + legacy; assert
A named/B untouched. Genuine RED-on-revert: revert = verb disabled
(unknown-verb → clearErr, no success line) or discovery pointed back at the
mirror scan (A survives, commit nil) — RED; fix on — PASS. The verb-mock RED
leg MUST exercise the old discovery and the replacement-identity race, not just
return A from an otherwise unchanged mock.
- Protocol-state contrast (ordinary CI): `complete=true` with zero matches
  returns `nil` and emits the success line; a nil capture selects the legacy
  producer; `complete=false` joins `clearErr` and suppresses success. The cell
  asserts these three states remain distinct, so an authoritative empty is
  never manufactured from a missing or incomplete capture.
- Clear-all contract re-pins for `mirror_clear_chunk`: #9364 control-2
  (`ClearAllSessions` stays bare at the public boundary while the helper
  enumerates all domains natively); #5881 (helper-error propagation returns
  first-error status); #5304 (every key is handled by helper-owned internal
  enumeration); #5380 (fast-fail across chunks on `helper_unavailable`, with
  no per-chunk deadline stacking).
- #10513 scoped-helper error controls (ordinary CI, v4 and v6): transport
  failure and semantic refusal must surface through
  `surfaceScopedHelperDeleteError`; helper failure wins over mirror
  `ErrKeyNotExist`, real mirror errors join, ENOENT remains hidden from the
  session-store NotFound classifier, and healthy helpers return clean while
  all requests reach the helper. The typed `mirror_delete_batch`/`TupleGate`
  result must preserve these boundary contracts rather than turning a
  refusal or `unknown_outcome` into `Noop`.


Guard cells: B-preservation (§2.3 proof items 1-4); id-0-collision
(first-policy A delete selected by its bound rule-handle, colliding zero-carrier
B remains on helper + BPF mirror + standby while unrelated zeros survive, and
#9526 purge still owns only A); companion/NAT (SNAT/DNAT/NAT64 colliding tuple
→ A's independently identified forward/reverse companions removed, B's intact,
no translated-tuple mistarget, changed companion preserved as
`partial_companion`); version-skew fail-closed (unknown-verb → clearErr, no
success line, no fallback); partial-worker-failure (per_worker_errors → joined
error + matches-in-hand fan-out attempted); standby-refusal (bare delete never
sent for a colliding tuple; incapable-peer withhold counter increments);
capture→publish residual pin (admission after a worker cursor survives to idle);
capture→replacement→delete (A captured, A expires, same tuple installs C,
delayed delete carries A's forward RT_FLOW id and leaves C + its mirror/standby
copies intact).
- Helper-first HA-import/delete race (privileged helper test, v4 and v6):
  use separate barriers for both acquisition orders. Delete-first pauses the
  policy delete after the helper enters `Held`/`Finalizing`, queues the HA
  import before its helper gate acquisition, and asserts the import performs
  no BPF syscall until final survivor repair/release. Import-first pauses the
  HA import after the helper acquires its `GateLease` but before its
  `SessionTable`+BPF mutation, queues policy delete, and asserts delete waits
  for import completion; then the conditional A removal preserves the imported
  different-identity row. Repeat with reverse-only `mirror_publish_only` to
  prove it never inserts a standalone helper row. Hold the import barrier past
  the internal 200ms worker deadline and restart the helper; assert the old
  epoch is rejected, the Go retry reissues one new epoch-scoped operation id
  carrying the same logical identity after reconcile, no token self-blocks,
  no A resurrection occurs, and no B is lost.
- Clear-fence vs tuple-GateLease race (privileged helper test, v4 and v6):
  tuple-first pauses `mirror_delete` in `Finalizing` after it holds shared
  `ClearAdmission` and `GateLease A`; `mirror_clear_chunk` requests `Draining`
  and must wait for final probe/repair and A release before exclusive
  `ClearFence`. Assert no post-fence A ack can publish or resurrect A, and
  clear completes its bounded chunk under one fence token. Clear-first enters
  `Draining`/`Held` before a queued stale-A delete and different-identity B
  import; assert neither queued operation reaches BPF during clear, A delete
  re-probes to `Noop` after release, and only explicit B import applies. Hold
  the clear callback on its exclusive token and assert table/mirror callbacks
  do not self-block or reacquire normal admission; repeat reverse-only import
  and assert no clear/delete interleave or post-clear resurrection.



Process: tests first, RED on base where the defect exists (T1–T8 + protocol
contrast + cross-process race + clear-fence race + revert legs), then
implement; record exact `go test`/`cargo test` invocations with lane-isolated
caches in the implement PR; affected suites green per §9.

## 6. STEP-0 verification (condensed; v1 §1 in history)

Issue OPEN; no merged/open PR or commit for #10512 at base; live on HEAD by
source: PolicyID-only predicates in BOTH producers
(daemon_policy_invalidate.go:449-477, capture.go:210-237) over the bare-keyed
BPF mirror (`SessionKey` types.go:12-20/v6; BPF key constructors
bpf_map/mod.rs:547-583; `BPF_ANY` last-writer-wins both families,
publish_conntrack.rs:138-145/390-397); empty→nil success
(daemon_policy_invalidate.go:529-532); per-domain helper authority
(session/key.rs:66-157); value-carried domain cannot de-alias
(docs/log/9546.md:28-30); no policy-enumeration helper verb in dispatch
(handlers/mod.rs:262-472). Siblings #10513/#10528 are distinct roots —
out of scope.

## 7. Source map (v1 §2 + v6 pins)

Invalidation: `pkg/daemon/daemon_policy_invalidate.go` (id sets :93-118 +
:631-651, clears :154-167/:201-215/:272-284, core :406-507, delete site
:529-595, join :360-379), `daemon_policy_invalidate_capture.go` (:124-126
arm, :149-246 capture, :103-112 authoritative-empty), arm sites
`daemon_apply_commit.go:284,663,949`, capture point
`daemon_apply_dataplane.go:171`, #5578 join `daemon_apply_commit.go:310-351`.
Mirror: `pkg/dataplane/session_store.go` (ForEach :221-233, scoped keys,
`DeleteBatchKnown`, `DeleteWithCompanionsV4` :888-899,
`deleteAppliedMirrorRows` precedent via userspace manager);
`pkg/dataplane/userspace/manager_sessions.go:37,107,132,189,194,201,236,
248,283,288,346,425,493,508,537,563,590,643,653,704,769` (21 current
direct mutation callsites; `ClearAllSessions` wrapper :743 drives the clear;
all cut over to helper-first RPC); `pkg/dataplane/maps_session.go`
iterators, `types.go` keys/values, `bpf_session_value.go` domain slot; Rust
`userspace-dp/src/server/handlers/mod.rs` mutator dispatch and
`userspace-dp/src/session` TupleGate/SessionTable transaction; Rust
`bpf_map/mod.rs` (keys :547-583, refresh :1035-1100, conntrack delete
:913-939, dispatch :200-260/:262-472),
`publish_conntrack.rs` (publishes + row-domain stamp :154-176),
`session/key.rs` + `session/entry.rs:241,308` + `session/mod.rs`
(bounds/ownership) + `policy.rs:1801-1819` (re-resolve) + `session_glue`
terminal delete (reviewer-verified collision work site).
HA: `pkg/cluster/sync_conn_write.go:194-233` (bare QueueDelete + suppressor
precedents), `sync_protocol.go:479-523` (bare delete encoding),
`sync_conn_gen.go:1203-1227` (bare standby apply + bare recv-identity),
`sync_session.rs:249-323` (probe + #8636 refusal), `protocol.go:335` /
`control.rs:197,311` (v30 floor, 64MB cap).
Tests: existing contract cells `daemon_policy_invalidate_test.go`,
`policy_reused_id_capture_6948_test.go`,
`policy_reused_id_overclear_6948_test.go`, `daemon_policy_modified_4234_test.go`,
`daemon_policy_default_4342_test.go`, `policy_rematch_shipped_6723_test.go`,
`batch_delete_domain_9364_test.go`, `batch_delete_mirror_domain_9546_test.go`,
`sync_delete_domain_9146_test.go`,
`batch_delete_helper_error_10513_test.go` (scoped helper-error surface,
precedence, ENOENT masking, and healthy-helper controls).

The userspace manager's direct session-map mutation surface is a required
cutover boundary: all listed `bpfShim` writers become helper-first RPC
wrappers, including reverse-only `mirror_publish_only`, forward transactional
upsert, helper-disposition deletes, and map-clear chunks. The helper control
protocol, TupleGate/SessionTable transaction, restart epoch, and ordinary
CI/privileged race cells therefore join the blast radius; no Go direct-write
fallback is permitted.

Post-rebase drift disposition: `filters.go` and `protocol_policies.go` carry
the unrelated #10514 NextTerm disclosure change; it does not alter the frozen
policy-id capture predicate and remains out of scope. `manager_sessionsync_transmit.go`
now documents #10513 scoped-batch first-error propagation, so that contract is
in scope here; the helper-first verb result must preserve its surface/Join/
precedence behavior rather than restoring a best-effort discard.
Implementation pins for the merged #10513 contract are
`manager_sessions.go:602-610` (`surfaceScopedHelperDeleteError`) and
`manager_sessionsync_transmit.go:182` (`syncSessionRequestsLocked` first-error
return); helper-first implementation must preserve both.

## 8. Blast radius (v1 §3 corrected)

3 arm sites, 1 capture site, 3 clears + shared core + shared delete site, 2
producers × 2 families (both must change together). Mirror consumers sharing
the row: GC (`pkg/conntrack/gc.go`), bulk (`pkg/cluster/sync_bulk.go`
forEach — reviewer 1-line drift noted vs v1's 235,247), conn sweep
(`sync_conn_sweep.go`), HA reconcile (`daemon_ha.go`), stale reconcile
(`session_store.go`), plus show/clear surfaces. CORRECTIONS to v1: (a)
current protocol floor is v30, not "v16+" (protocol.go:335,
control.rs:197); (b) the helper verb touches producers + verb + HA wire (§1)
+ mirror-delete path (§2), not "producers only"; (c) discovery output keeps
producing `SessionEntry` with trustworthy `RoutingDomain` (verb matches
carry it) so the #9364/#9714/#9752 scoped-delete cells stay meaningful.
Suites that must stay green: `pkg/daemon`, `pkg/dataplane/...`,
`pkg/conntrack`, `pkg/cluster`, `userspace-dp` session/bpf_map/server.
Privileged cells skip without CAP_BPF (#9337); T1–T8 need the privileged
cluster.

## 9. Root cause (unchanged from v1)

Discovery and authority disagree by construction. Authority (helper
`SessionTable`, HA-synced store) is keyed per routing domain; discovery (Go
`ForEachV4/V6` over the BPF conntrack mirror) is keyed on the bare 5-tuple
and keeps one row per tuple under `BPF_ANY` last-writer-wins. The
invalidation predicate (`val.PolicyID in deletedIds`) is evaluated against
the surviving row only, so when the survivor belongs to the non-deleted
tenant the deleted tenant's sessions are never named, the candidate set is
empty, `deleteInvalidatedSessions` returns nil, and the commit reports
success with stale helper sessions still installed. #9546's value-carried
domain fixes WHICH domain a selected row deletes in; it cannot surface a row
the key collision already discarded.

## 10. Fix options (decision recorded)

Option A (CHOSEN, READ-verb shape per Q1): `list_sessions_by_policy` +
Go-orchestrated scoped deletes (§1–§4). Puts the predicate where the index
exists; bounds the change to producers + one verb + HA wire widening +
collision-aware mirror delete; reuses scoped-delete + #5578 machinery.
Option B (per-domain mirror: B1 key widening / B2 secondary index):
rejected for this fix — multi-PR 3-language ABI crossing (B1) or doubled
hot-path write fan-out with consistency hazards (B2); B1 as long-term
end-state is a follow-up tech-debt FILING, not an assumption — it needs a
shim-domain feasibility proof first (the mirror is shim-probed; the shim
would have to resolve config-derived FNV domains at probe time). Implement
lane files that issue. Option C (Go-side index): rejected — silent drift
across every mutation source (frame installs, HA import, #3395 re-stamps,
GC, clears, promotion, restart) trades a visible miss for invisible index
rot.

## 11. Risks (v1 §7, each now pointing at its closer)

Silent-skew → §4 mapping table + positively-known-empty rule. Valid-commit
over-clear → §3 frozen ids + mode-specific fence + RT_FLOW identity guards.
Old-numbering window → §3 placement + explicitly widened bounded residual.
Companions → §2.1 forward-only + independent local identities + peer forward
identity derivation. id-0 → §2.1 selective #9526 coordinator repair and B
preservation. Standby/no-packet → §1.3 traces + §5 T8. Version skew → §4
floor + withhold + guidance. Two-producer/two-family → §3 legacy rule + §5
T1–T4. Siblings → still out of scope (#10513, #10528).

## 12. Implement-lane execution sketch (after plan approval)

Lane-isolated caches under `/dev/shm`; assigned worktree/branch only; no
merges, no reviewer dispatch (parent owns), and no cluster/incus commands.
Tests first (§5), RED on base, then implement §§1–4.
Minimal diff: both producers, both families, same three id sets, same
delete/HA-sync machinery shape, plus the helper-first cutover of every listed
Go session-map mutation to `mirror_upsert`, `mirror_publish_only`,
`mirror_delete*`, or `mirror_clear_chunk`; no direct Go BPF fallback.
RED-on-revert firsthand, affected suites (§8), rebase on `origin/master`, PR
with `Closes #10512` + Why/What/Validation body, report + STOP.


## 13. Deliverable checklist

- [x] Round-1 fold: both reviewer reports read in full; findings mapped
  (A F1→§2, F2→§1, F3→§3, F4→§3, F5→§4, F6→§5, F7→§2+§3, F8→§4, F9→§4,
  F10→§8, F11→§10; B F1→§1, F2→§2, F3→§3, F4→§3, F5→§4, F6→§5, F7→§0).
- [x] Parent closures Q1/Q2/Q3/Q4/Q5 recorded as decided (§0); Q6 filed as
  follow-up; boundary honored (HA/standby in scope; no GC-will-heal claim).
- [x] Required blocks present: (1) HA §1 with wire + traces, (2) mirror §2
  with return shape + rule + proof, (3) predicate+timing §3, (4) bounds+
  failure §4, (5) tests §5 (3 classes × 2 families × 2 producers + guards).
- [x] No production code touched; plan-only diff.
- [x] Fold-2 Delta2 R1/R2: tuple-gate permits/finalization/liveness/proof and
  bounded delete batching/deadlines/completion/#5578 mapping are recorded;
  Delta2 R3–R6 remain deferred per the parent brief.
- [x] Fold-3 V4: helper-first migration covers every production Go
  session-map mutation (including HA imports, reverse-only publication, and
  #5305 compensation); per-key GateLease/restart epoch/reissue semantics are
  specified, and the HA-import/delete race cell is present; NR-1 positive-empty,
  NR-2 skew, and NR-3 retry/convergence corrections are recorded.
- [x] Fold-4 V6: Delta1 NR-4 clear-all contract repins and Delta2 NR-5/NR-6
  clear-fence/reconcile-quarantine semantics are recorded; the post-rebase
  #10513 mutation audit, scoped error surface/Join/precedence contract, and
  clear-fence race/process cell are pinned against origin/master.
- [x] DRAFT v6 plan force-added and committed; branch publication handled
  outside this document.
