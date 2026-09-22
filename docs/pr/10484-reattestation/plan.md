# DRAFT v1: #10484 live re-attestation proving the D11 join before S9.5 relies on the bridge

Status: DRAFT v1 for hostile plan review. No production code. No live run performed in-lane
(cluster/incus commands are forbidden in this lane; the attested run is prescribed for a
lab-capable lane). All source citations are grounded at base 25e0da53c
(daemon: publish per-admitted IPsec tunnel rows (#10485)) in worktree
fix/10484-reattestation.

## 1. Problem restatement (from source, not memory)

Issue #10484 is the mandatory follow-up to the #10483 merge-gate ruling (both hostile
reviewers + parent). PR #10483 squash-merged as b71c52d6093f with BOTH live attestation
attempts VOID:

- Attempt-1: VOID wrong-binary. exe_check=UNAVAILABLE, local_exe_sha=unknown, both
  firewalls on cf654836..45bae. Fixture was present (stn=1, xfrm_sa=1,
  complete_fixture=1), so attempt-1 is not fixture evidence.
  Archive: /var/tmp/xpf-t12-g2-9506-1789902213. Log: docs/log/9506-mech.md:42-81.
- Attempt-2: VOID fixtures-missing with exe_check=MATCH (all three SHAs
  d5e18a0b..da63 at git_sha 957b37f4c). Exact failure at fixture setup:
  RPC FailedPrecondition "local redundancy group 2 not ready for explicit failover",
  reasons=[userspace helper not enabled, userspace forwarding unsupported, userspace
  forwarding not armed, userspace XSK liveness not proven].
  Preconditions all zero: stn=0 xfrm_sa=0 divert_table=0 complete_fixture=0.
  Archive: /var/tmp/xpf-t12-g2-9506-1789904125. Log: docs/log/9506-mech.md:83-126.

Merge-safe per the dark-by-design triple inertness (issue body): Go never submits,
empty Rust tunnel rows E28-deny, advisory generations unaligned. The attestation budget
was declared exhausted with no further live run or fixture repair attempted.

Required now: a valid (non-VOID) live run of test/incus/t12-g2-9506.sh proving the D11
join end-to-end (submit -> verdict -> completion join) BEFORE S9.5 / the counter slice
relies on the bridge. Fixture prerequisites from attempt-2 must be repaired first.
Acceptance: ledger with cells passing on a live cluster at a commit containing
b71c52d6093f, exe_check=MATCH, fixtures converged, traffic attributed.

## 2. STEP-0 live evidence (this lane, firsthand)

- Issue state: OPEN, needs-work, 0 comments (gh issue view 10484 --json). Body quoted
  verbatim in section 1 from artifact read.
- Not already fixed: git log --all --grep=10484 is empty; gh pr list --state merged
  --search "10484" and "re-attestation D11" return zero rows; no merged PR closes it.
- Base contains the bridge: b71c52d6093f IS an ancestor of HEAD 25e0da53c
  (git merge-base --is-ancestor: yes). The pre-squash branch commits (957b37f4c,
  4e01cb956) are NOT ancestors: expected, #10483 squash-merged. Acceptance names
  b71c52d6093f, which is present.
- Proof-script health: ./test/incus/t12-g2-9506.sh --selftest => 63 passed, 0 failed
  (hermetic, cluster-free). Parsers and refusal model intact on this base.
- Advisory weighed: the blocker advisory asked for the exact live with-cluster.sh
  command. Refused for this lane: the lane assignment explicitly forbids cluster/incus
  commands, and the shared-cluster lock (test/incus/with-cluster.sh:160-206, slave
  guard test/incus/t12-g2-9506.sh:1406-1409 + fix9506_require_lock at
  test/incus/ipsec-9506-fixture.sh:92-96) would contend with concurrently running
  sibling lanes. Selftest + helper inspection (the advisory's cluster-free steps) are
  done above; the live attempt belongs to the lab lane in section 7.

## 3. D11 join + S9.5 bridge-reliance located in source

D11 join path (all lines at 25e0da53c):

- Rust submit ingress: userspace-dp/src/slowpath.rs:661-663
  (ipsec_inner_v1_enabled + IpsecInnerWorkerTransport), :888/:949 constructor wiring,
  :1330 dispatch into submit_ipsec_inner_v1, :1477 join call into the reinject core.
- Rust verdict join: userspace-dp/src/slowpath_reinject_9506.rs:1031
  resolve_ipsec_inner_verdict maps IpsecInnerVerdict::{Deny, WouldPermit} to
  Go-facing completions; never a q0 write (doc comment :1029-1030).
- Rust verdict transport: userspace-dp/src/afxdp/ipsec_inner_queue.rs
  IpsecInnerVerdict enum (:179-193, Deny | WouldPermit only), try_post, per-worker
  post_worker_verdict; userspace-dp/src/afxdp/ipsec_inner.rs:320
  post_ipsec_inner_verdict (full queue is E24 terminal); worker drain in
  userspace-dp/src/afxdp/worker/loop_body/mod.rs.
- Go completion half: pkg/nfqueue/reinject_socket.go:538 outcome code 10 ->
  CompletionWouldPermit; pkg/nfqueue/pipeline.go:962 WouldPermit ->
  V1PermitSuppressed accounting.
- Go DARK (merge-safety leg 1, still holds): pkg/nfqueue/pipeline.go:704-712,
  submitEligible unconditionally suppresses every zone-passing frame
  (V1PermitSuppressed++, VerdictDrop). Callers at :461 and :1133 pass through the
  same gate. The only submitter operations invoked anywhere are AnnounceReinject,
  CancelReinject, and DrainReinjectCompletions: NO Submit call exists in the tree.
  Go never submits. Confirmed by grep over pkg/nfqueue + pkg/daemon.

S9.5 (future-only; zero code, five comment sites):

- userspace-dp/src/afxdp/ipsec_inner.rs:120-123: no permit arm on this Rust path
  until S9.5; successful adjudication returns outcome code 10 (WouldPermit, not E28).
- userspace-dp/src/afxdp/ipsec_inner.rs:281-288: S9.5-removal comments at every
  would-join site: no session install, flow-cache publish, NAT mutation, q0 enqueue,
  or NF_ACCEPT in V1.
- userspace-dp/src/afxdp/ipsec_inner_queue.rs:748-750: permit paths register on the
  S9.5 join (ProvisionalJournal is reaper-contract + fault-injection only in V1).
- userspace-dp/src/afxdp/ipsec_inner_queue.rs:1569: E29 fires only via fault
  injection in V1.
- docs/log/9506-mech.md:6-8: policy/permit behavior (S9.5), counter follow-ups, and
  later slices are out of scope for the mechanism phase.

Sequencing fact: #10485 (per-admitted tunnel-rows publisher) has MERGED as the base
commit 25e0da53c. The merge-gate sequencing was 10485 -> 10484 -> counter slice; the
first leg is done. Dark-triple leg 2 ("empty Rust tunnel rows E28-deny") MUST be
re-grounded at this base during implementation (section 6, item Q4): the publisher now
exists, so the lab lane must state which inertness legs still hold and cite rows.

## 4. Blast radius

| Item | Number | Source |
| --- | --- | --- |
| Mechanism merge b71c52d60 | 33 files, +7043/-360 | git show --stat |
| Rust D11 bridge 957b37f4c (pre-squash) | 8 files, +520/-43 | git show --stat |
| Live D11 symbol span | 10 files: pipeline.go, reinject_socket.go, pipeline_9506_test.go, reinject_socket_9506_test.go, slowpath.rs, slowpath_reinject_9506.rs, slowpath_reinject_9506_tests.rs, ipsec_inner.rs, ipsec_inner_queue.rs, worker/loop_body/mod.rs | grep D11 symbol set |
| S9.5 code | 0 files; 5 comment sites | scoped grep S9.5 |
| Proof script test/incus/t12-g2-9506.sh | 2347 lines, 30 ledger rows, 0 D11-specific cells (grep d11/D11: no hits) | wc + grep |
| Fixture helper test/incus/ipsec-9506-fixture.sh | 1054 lines; setup chain rg_record -> rg_failover(2->node1) -> wait_outer_paths -> peer_up -> gen_config -> commit_file -> install_inner_routes -> converge -> queue-witness | read :856-929 |
| Attempt-2 failure point | fix9506_setup rg_failover step (:887) via firewall RPC | 9506-mech.md:95-100 |
| Unconditional VOID measurement cells on base | fence_shape, divert_order, no_bypass, vrf_refusal, coexistence_order, provenance_metadata (verdict-flip-owned-by-v-flip), ifindex_recreate, bridge_conformance, l2_refusal, rotation_atomicity, integration_ownership, pf_bind_scope, all G2 workload cells (verdict-flip-unimplemented) | t12-g2-9506.sh:2125-2283 |

Gate: DESIGN (recorded 2026-09-22). Mechanical is refused for three independent
reasons, any one sufficient: (a) acceptance is a live-cluster PASS ledger and this
lane cannot run cluster commands; (b) no mechanical source defect exists --
attempt-2 was environmental (cluster userspace unarmed), the script already refuses
conservatively, and Go suppression is intentional per the merge-gate ruling;
(c) the D11 join measurement does not exist anywhere (zero D11 cells; verdict-flip
observers unimplemented), so the work is new measurement design plus a cutover
decision, not a bounded fix. Un-darkening Go submission without the S9.5 safety case
would violate the ruling both reviewers relied on.

## 5. The cutover paradox (central design question for review)

The default product path never submits (section 3), so the join is unreachable
without an explicitly guarded attestation seam. The seam must prove the bridge
before S9.5 lands while preserving the default dark behavior.

- Option B (RECOMMENDED): reuse the existing Go client through an explicit,
  authenticated lab trigger. The trigger is a small daemon/pipeline seam, not a
  second reinject-socket client. It accepts only frames captured by the fixture's
  NFQUEUE path plus a run nonce and per-frame attribution manifest; arbitrary raw
  bytes from a caller are rejected. It reuses the normal zone gate and lease
  mint, inserts the matching p.pending entry, and calls the existing
  SocketReinjectSubmitter.SubmitAdjudicated path. Go therefore remains the sole
  submit and completion-socket client, and its normal drain resolves the terminal
  WouldPermit/Deny completion against the exact captured frame.
  The trigger is deny-only and one-shot: it requires explicit lab attestation
  authorization, P-MECH admission DENY_ONLY, permit CLOSED, current generation
  and lease authority, and it cannot enqueue q0, install a session, mutate NAT,
  or NF_ACCEPT. After Go drains, the harness joins request_id/lease/origin and
  the exact frame digest from its manifest to the Rust
  ReinjectStatusSnapshot provenance row. This proves the D11 bridge with the
  existing singleton sockets and records Go V1PermitSuppressed accounting without
  weakening the merge-time dark default.
- Direct socket variant (REJECTED): a second harness connection cannot own either
  submit or completion while Go retains its long-lived streams
  (server/reinject_9506.rs:317-362). A close/reannounce handoff would need to
  quiesce pending state, prove deny-only authority, transfer both streams, and
  restore/re-announce Go; it is needlessly invasive and is not the acceptance
  path.
- Option C (REJECTED): land the Go cutover as part of this issue. That is the S9.5
  and counter-slice scope (session/NAT/q0 guards, supervisor committer, rollback)
  and inverts the mandated sequencing. This is a PLAN-KILL trigger if the guarded
  lab trigger cannot preserve every deny-only predicate above.

## 6. Resolved questions and implementation gates

- Q1 (join observability, resolved): pipeline.go:925-936 requires
  p.pending[request_id] before a completion can affect a frame or increment
  V1PermitSuppressed. The guarded lab trigger uses the existing Go client, inserts
  that pending entry for the exact captured frame, and calls the normal
  SocketReinjectSubmitter.SubmitAdjudicated path. Go remains the sole submit and
  completion-socket client (server/reinject_9506.rs:343-362), so the harness
  observes Go's resolved completion/stat counters while the authenticated Rust
  ReinjectStatusSnapshot provenance row independently matches request_id, lease,
  origin, and frame digest. An unknown or duplicate completion, or a missing
  provenance row, is a FAIL rather than a successful late-completion observation.
- Q2 (26B tail contract): cite the exact tail builder/validator pair
  (Go SubmitBatchPMechTail* test family plus Rust strict-26B-tail admission from
  a02639396) that the guarded trigger must satisfy, including flags and advisory
  generation values valid post-#10485.
- Q3 (workload shape and binding): use v4_native x2 minimum, one even/RG1/fw0
  and one odd/RG2/fw1 (fixture_probe_indices at t12-g2-9506.sh:96-102 and
  fixture_measure_traffic :1440-1491). Every generated packet gets a unique
  payload marker and a manifest row containing the exact bytes digest, origin
  family/hook/owned-ifindex/owner/STN, queue number/epoch, and the request_id
  assigned by the guarded trigger. The D11 observer must match that request_id,
  lease identity, origin identity, and marker/digest witness in its provenance
  record before counting traffic. Per-node XFRM if_id 0x25220001/2 deltas
  corroborate fixture readiness only; unrelated deltas alone can never satisfy
  attribution. If the running status surface cannot expose the marker/digest
  witness, add that exact field to the authenticated provenance surface or leave
  the D11 row VOID; never infer it.
- Q4 (dark-triple re-grounding at 25e0da53c): leg 1 holds (Go never submits in
  the default path, section 3). Re-verify legs 2-3 (tunnel-row E28-deny posture
  now that the #10485 publisher exists and advisory-generation alignment) with
  row-level citations before the run, and record which legs the run relies on.
- Q5 (cluster repair ownership): the lab operator owns the RG2/userspace-arm/XSK
  repair. The pre-run convergence checklist must turn attempt-2's
  FailedPrecondition into has_st=has_sa=has_divert=1 on both nodes before any
  D11 cell can leave VOID.

## 7. Recommended shape (lab lane, not this lane)

Slice 1 -- join semantics lock (source-only, no cluster):
  a. Freeze the Q1 guarded-trigger contract and Q2 tail bytes with file:line
     citations; pin the completion observer as Go's resolved completion plus the
     authenticated Rust provenance row, never a second socket reader.
  b. Verify the D11 unit proofs still pass at the run commit (cargo
     ipsec_inner_queue 18 cells, ipsec_inner_verdict_bridge 2 cells,
     reinject_9506 66 cells; Go AdmissionReasonConsistency /
     SubmitBatchPMechTailTwoFrames / ExtendedCompletionOutcomes) as the pre-live
     gate. Any failure is PLAN-KILL for the run until fixed upstream.
Slice 2 -- guarded Go trigger plus cells (narrow mechanism seam plus script):
  a. Add an authenticated, one-shot lab trigger in daemon/pipeline wiring that
     accepts only fixture-captured frames and their attribution manifest. It must
     reuse zone validation, lease minting, the existing Go submit client, and the
     normal completion drain; it must create matching p.pending entries before
     submit. The trigger is deny-only under P-MECH DENY_ONLY, permit CLOSED, and
     current generation, and cannot enqueue q0, install a session, mutate NAT, or
     NF_ACCEPT. It is disabled by default and has explicit authorization, nonce,
     and teardown/restore checks. No direct submit/completion socket client is added.
  b. Extend the authenticated Rust provenance/status row only as needed to expose
     the exact frame digest/marker alongside request_id, lease, and origin; a
     missing witness remains VOID. The harness driver sends the captured frame
     manifest through the trigger and records request IDs, admissions, Go terminal
     outcomes, and Rust provenance joins.
  c. Add D11 join cells (exact predicates for review):
     d11_9506_submit_admit (captured frames admitted on both nodes with matching
     request/lease identity), d11_9506_worker_verdict (worker verdicts split
     Deny/WouldPermit, never q0), d11_9506_completion_join (each request joined
     exactly once by Go and Rust, no duplicate or late completion), and
     d11_9506_wouldpermit_accounting (outcome-10 maps to Go
     V1PermitSuppressed, never E28; E28 byte-52 stays zero).
  d. Add an explicit --d11-reattest mode to this same script. It reuses the exact
     fixture setup, executable attestation, runtime observers, trigger driver, and
     teardown/residue checks, but buffers and emits only the four D11 rows above.
     Its acceptance gate is D11_CELL_COUNT==4, all four rows PASS, zero VOID/FAIL,
     and exit 0. The existing no-argument mode remains the conservative 30-row
     T12/G2 suite: unrelated measurement-incomplete rows stay VOID and are never
     represented as #10484 evidence. This mode does not weaken the default suite
     or claim that suite passed.
  e. Extend --selftest with hermetic trigger authorization, attribution, and
     D11-mode shape/refusal cases (mirroring cell_verdict conservatism at
     :986-1003). D11 rows MUST default to VOID with explicit reasons until the
     live path proves them.
Slice 3 -- cluster repair runbook (operator/lab):
  a. Repair attempt-2 prerequisites in order: userspace helper enabled ->
     forwarding supported and armed -> XSK liveness proven -> RG2 ready
     (fix9506_rg_failover 2 1 succeeds) -> fix9506_converge stn=2/2,
     SA egress/ingress, queues, and nft=1/1.
  b. Deploy gate: XPF_DEPLOY_FAST=1 make cluster-deploy from a clean tree at a
     commit containing b71c52d6093f; pre-run executable SHA verification on local,
     fw0, and fw1 (attempt-2 procedure at 9506-mech.md:85-91, which achieved MATCH).
Slice 4 -- attested run:
  ./test/incus/with-cluster.sh '9506 mech reattest' -- \
      ./test/incus/t12-g2-9506.sh --d11-reattest
  Single run; no rerun-and-tune. The D11-specific ledger is the acceptance artifact;
  the ordinary 30-row T12/G2 ledger is not claimed to pass. Preserve both the D11
  archive and the full observer snapshots.
Slice 5 -- record and close:
  Append the run record to docs/log/9506-mech.md (or docs/log/10484.md), file the
  D11 ledger, and close #10484 only if section 8 holds. #9506 stays OPEN (counter
  slice pending) per campaign tracking.

### 7.1 Ledger convergence and acceptance boundary

The existing script has 30 rows and exits 2 when any row is VOID (:2320-2347).
Several of those rows are intentionally unrelated measurement-incomplete cells
(exact pinholes, VRF, rotation, queue economics, and the future verdict flip), so
merely appending four D11 rows would make a successful D11 run impossible. The
--d11-reattest branch MUST therefore select the D11 row buffer before the existing
30-row emission loop, run the shared setup and restore proof, and use a separate
exact four-row count. It MUST not relabel, delete, or silently pass the ordinary
rows.

The accepted #10484 run is consequently explicit:
`t12-g2-9506.sh --d11-reattest` with `T12_D11_SUMMARY cells=4 pass=4
fail=0 void=0 exe_check=MATCH`, converged fixtures, per-request attribution, and
clean restore. The no-argument script remains useful for the broader r6 ledger but
is not the acceptance command for this follow-up while its unrelated cells remain
VOID.

## 8. Proof cells and kill-gates

The accepted --d11-reattest PASS requires ALL of: exe_check=MATCH
(local==fw0==fw1, t12-g2-9506.sh:1687-1697); complete_fixture=1 with
stn/xfrm_sa/divert_table all 1 on both nodes (:1900-1902); each node offers
captured fixture frames with a manifest binding exact bytes digest, origin,
queue/lease identity, and request_id; every request_id is admitted, receives
exactly one Rust worker verdict, and is resolved exactly once by Go
(completion accounting balanced, no late or duplicate IDs); the Rust provenance
row matches each manifest request_id/lease/origin/digest; WouldPermit outcome 10
increments Go V1PermitSuppressed and contributes zero E28 byte-52 events; and
shared restore is clean (fw0/fw1_config_cmp=1, residue clear, probe errors=0).
The mode emits exactly four D11 rows, all PASS, with no VOID/FAIL, and exits 0.
These are the only rows used to close #10484; the ordinary 30-row mode remains
a separate broader ledger.

In --d11-reattest mode, VOID (never PASS, never FAIL) means exe_check != MATCH,
fixture-setup-failed (any fix9506_setup step, including RG2 failover), no
captured frames, or any required observer surface unavailable (Rust status, Go
metrics, nfqueue, st-links, or attribution digest). A VOID run is retained as
diagnostic evidence but cannot close the issue.

FAIL (claim broken, not environment): completion joined to a wrong request_id;
duplicate or late completion; provenance identity/digest mismatch; verdict
observed on the q0 path; WouldPermit misclassified as E28; V1PermitSuppressed
not incremented for a matched outcome-10 completion; PASS emitted before restore;
D11 ledger row-count mismatch; or any D11 row silently omitted. Any FAIL kills
the run: no close.

PLAN-KILL boundaries: the guarded trigger cannot preserve deny-only predicates;
the Rust provenance/status surface cannot expose an authoritative
request_id/lease/origin/digest witness; dark-triple re-grounding (Q4) shows the
run would need the S9.5 cutover; or cluster repair (Q5) leaves userspace arming
unsupported. In any such case the sequencing returns to the owner for re-scope,
exactly as the P-MECH PLAN-KILL boundary precedent requires.
