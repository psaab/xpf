# DRAFT v2: #10484 live re-attestation proving the D11 join before S9.5 relies on the bridge

Status: DRAFT v2 for delta re-review. Folds round-1 hostile reviews (both
PLAN-NEEDS-MAJOR, convergent, no KILL): reviewer A (E28-impossible cell,
trigger-underspec, provenance-gap, predicates, citations) and reviewer B
(F1 permit contradiction, F2 E28, F3 provenance auth, F4 singleton/location,
F5 pending lifecycle, F6 mode gaps, F7 runbook, F8 boundary-holds). No
production code. No live run performed in-lane (cluster/incus commands are
forbidden in this lane; the attested run is prescribed for a lab-capable
lane). All source citations were re-grounded at base `25e0da53c` for this
DRAFT v2 via `read`; grep snapshots drifted by 2 lines in `pipeline.go` during
grounding, so every line cite below is read-verified against that base. New
(designed, not yet in tree) symbols are explicitly marked NEW; everything else
must already exist at the cited file:line.

## 1. Problem restatement (from source, not memory)

Issue #10484 is the mandatory follow-up to the #10483 merge-gate ruling (both
hostile reviewers + parent). PR #10483 squash-merged as b71c52d6093f with BOTH
live attestation attempts VOID:

- Attempt-1: VOID wrong-binary. exe_check=UNAVAILABLE, local_exe_sha=unknown,
  both firewalls on cf654836..45bae. Fixture was present (stn=1, xfrm_sa=1,
  complete_fixture=1), so attempt-1 is not fixture evidence.
  Archive: /var/tmp/xpf-t12-g2-9506-1789902213. Log: docs/log/9506-mech.md:42-81.
- Attempt-2: VOID fixtures-missing with exe_check=MATCH (all three SHAs
  d5e18a0b..da63 at git_sha 957b37f4c). Exact failure at fixture setup:
  RPC FailedPrecondition "local redundancy group 2 not ready for explicit
  failover", reasons=[userspace helper not enabled, userspace forwarding
  unsupported, userspace forwarding not armed, userspace XSK liveness not
  proven]. Preconditions all zero: stn=0 xfrm_sa=0 divert_table=0
  complete_fixture=0. Archive: /var/tmp/xpf-t12-g2-9506-1789904125. Log:
  docs/log/9506-mech.md:83-126.

Merge-safe per the dark-by-design triple inertness (issue body): Go never
submits, empty Rust tunnel rows E28-deny, advisory generations unaligned. The
attestation budget was declared exhausted with no further live run or fixture
repair attempted.

Required now: a valid (non-VOID) live run of test/incus/t12-g2-9506.sh proving
the D11 join end-to-end (submit -> verdict -> completion join) BEFORE S9.5 /
the counter slice relies on the bridge. Fixture prerequisites from attempt-2
must be repaired first. Acceptance: ledger with cells passing on a live cluster
at a commit containing b71c52d6093f, exe_check=MATCH, fixtures converged,
traffic attributed.

## 2. STEP-0 live evidence (this lane, firsthand)

- Issue state: OPEN, needs-work, 0 comments (gh issue view 10484 --json). Body
  quoted verbatim in section 1 from artifact read.
- Not already fixed: git log --all --grep=10484 is empty; gh pr list --state
  merged --search "10484" and "re-attestation D11" return zero rows; no merged
  PR closes it.
- Base contains the bridge: b71c52d6093f IS an ancestor of HEAD 25e0da53c
  (git merge-base --is-ancestor: yes). The pre-squash branch commits
  (957b37f4c, 4e01cb956) are NOT ancestors: expected, #10483 squash-merged.
  Acceptance names b71c52d6093f, which is present.
- Proof-script health: ./test/incus/t12-g2-9506.sh --selftest => 63 passed, 0
  failed (hermetic, cluster-free). Parsers and refusal model intact on base.
- Exact file/callsite counts (design-path record):
  - `submitEligible` definition pkg/nfqueue/pipeline.go:632; call sites exactly
    2: :463 (consumeFrames enforcing branch) and :1135 (Cancel scoped
    re-submit). Both pass through the same suppression gate.
  - `SubmitAdjudicated` production callers: 0. The interface method
    (pipeline.go:112) and socket implementation (reinject_socket.go:115) exist;
    production invokes only AnnounceReinject (daemon
    ipsec_capture_wiring_9506.go authoritySnapshot/announceAuthorityLocked
    region), CancelReinject (pipeline.go:749 via cancelUncertainLease, :1105 via
    Cancel), and DrainReinjectCompletions (pipeline.go:837 via Poll). Test-only
    invocations exist (reinject_socket_9506_test.go, reinject_announce_9506_test.go).
  - `p.pending` production inserts: 0. Production only reads/deletes
    (pipeline.go:927 lookup, :933 delete on resolve, :850-854 expiry,
    :1027-1034 scoped cancel). The trigger seam (section 5) is therefore the
    first production pending writer; its insertion protocol is specified there.
  - `DenyEvents:` production setters: 0 in pkg/daemon (grep; only test literals
    set it). Struct field pipeline.go:182, constructor passthrough :325. Go
    deny-52 events are therefore unobservable in production until Slice-2c wires
    a sink/export (section 6).
  - `xpf_ipsec_capture_*` metrics exported today: consumed, adjudicated,
    reinjected, written, uncertain, late_completions, timeouts, stale,
    cancelled, refused, delivered (pkg/api/metrics_descriptors_controlplane.go
    + metrics_ipsec_capture_10478.go:42-50 collector over
    IpsecCaptureWitness in pkg/api/server.go:101-120). No suppressed count, no
    deny-52 count: both are Slice-2c additions.
- Advisory weighed: the blocker advisory asked for the exact live
  with-cluster.sh command. Refused for this lane: the lane assignment
  explicitly forbids cluster/incus commands, and the shared-cluster lock
  (test/incus/with-cluster.sh:160-206, slave guard
  test/incus/t12-g2-9506.sh:1406-1409 + fix9506_require_lock at
  test/incus/ipsec-9506-fixture.sh:92-96) would contend with concurrently
  running sibling lanes. Selftest + helper inspection (the advisory's
  cluster-free steps) are done above; the live attempt belongs to the lab lane
  in section 7.

## 3. D11 join + S9.5 bridge-reliance located in source

D11 join path (all lines read-verified at tip):

- Rust submit ingress: userspace-dp/src/slowpath.rs:661-663
  (ipsec_inner_v1_enabled + IpsecInnerWorkerTransport), :888 prod
  (v1_enabled=true) vs :949 test (false), :1330-1331 dispatch into
  submit_ipsec_inner_v1, :1473-1477 complete_ipsec_inner_verdict into the
  reinject core.
- V1 admission order in submit_ipsec_inner_v1 (:1274-1321):
  reinject_core.admit_with_class (:1275-1280, authority/lease/origin/generation
  gates) -> slab acquire+copy (:1292-1304) -> D11 transport admit_descriptor
  (:1311-1319, STALE/SHUTDOWN/FULL/BAD_LEASE refusal mapping). Any refusal
  unwinds via refuse_queued (:1282-1290). V1 submits enter the Rust transport
  and never create a TUN PacketRequest (:1242-1246, :1270-1273).
- Rust verdict join:
  userspace-dp/src/slowpath_reinject_9506.rs:1028-1057
  resolve_ipsec_inner_verdict maps IpsecInnerVerdict::{Deny, WouldPermit} to
  Go-facing completions (Denied/Uncertain/WouldPermit); never a q0 write.
  Duplicate terminalize is refused (already-terminal guard :1366-1402).
- Rust verdict transport: userspace-dp/src/afxdp/ipsec_inner_queue.rs
  IpsecInnerVerdict enum (:179-193, Deny | WouldPermit only; WouldPermit at
  :190-192 carries request_id alone, no reason byte), try_post, per-worker
  post_worker_verdict; userspace-dp/src/afxdp/ipsec_inner.rs post verdict
  (:318-331 region, full queue is E24 terminal); worker drain chain in
  userspace-dp/src/afxdp/worker/loop_body/mod.rs:725-769 (drain_worker :725,
  adjudicate_descriptor :754, post_worker_verdict :756, drain_verdicts_into
  :762, complete_ipsec_inner_verdict :768-769). Note: worker adjudication sees
  descriptor fields with inner_packet=&[] (:731-733): content binding must be
  hashed at submit/admit time, not at the worker (section 6).
- Go completion half: pkg/nfqueue/reinject_socket.go:538-539 outcome code 10
  -> CompletionWouldPermit; pkg/nfqueue/pipeline.go:964-965 WouldPermit ->
  V1PermitSuppressed++; :983-985 WouldPermit -> emitDeny(ReasonEvaluatorUnavailable=52,
  :1316) + VerdictDrop. Terminal WouldPermit ALWAYS emits deny-52 when a sink
  is configured (comment :101-103 states the mapping explicitly); routine
  pre-submit suppression (:706-712) emits no event. The two modes must never be
  conflated (section 6).
- Go DARK (merge-safety leg 1, still holds in the default path):
  pkg/nfqueue/pipeline.go:706-712, submitEligible unconditionally suppresses
  every zone-passing frame (V1PermitSuppressed++, VerdictDrop). Callers at :463
  and :1135 pass through the same gate. No production Submit call exists (see
  section 2 counts).

S9.5 (future-only; zero code, four production comment sites + one test pin):

- userspace-dp/src/afxdp/ipsec_inner.rs:120-123: no permit arm on this Rust
  path until S9.5; successful adjudication returns outcome code 10 (WouldPermit,
  not E28).
- userspace-dp/src/afxdp/ipsec_inner.rs:280-288: S9.5-removal comments at every
  would-join site: no session install, flow-cache publish, NAT mutation, q0
  enqueue, or NF_ACCEPT in V1.
- userspace-dp/src/afxdp/ipsec_inner_queue.rs:746-750: permit paths register on
  the S9.5 join (ProvisionalJournal is reaper-contract + fault-injection only
  in V1).
- docs/log/9506-mech.md:6-8: policy/permit behavior (S9.5), counter follow-ups,
  and later slices are out of scope for the mechanism phase.
- userspace-dp/src/afxdp/ipsec_inner_queue.rs:1569 is a comment inside the unit
  test reason_map_is_closed_32_to_60_plus_legacy ("E29 fires only via fault
  injection in V1"), NOT a production gate: cited here only as a test pin, not
  as S9.5-absence evidence.

Sequencing fact: #10485 (per-admitted tunnel-rows publisher) has MERGED as the
base commit 25e0da53c. The merge-gate sequencing was 10485 -> 10484 -> counter
slice; the first leg is done. Dark-triple leg 2 ("empty Rust tunnel rows
E28-deny", coordinator/mod.rs:1639-1645 empty=>gen0, D14 exact gate
ipsec_inner.rs:182-213) MUST be re-grounded at this base during implementation
(section 6, item Q4): the publisher now exists, so the lab lane must state
which inertness legs still hold and cite rows. Anticipated outcome (to verify,
not assume): trigger selection is permitted only when rows are populated and
generations aligned, so the empty-row E28 gate is not exercised for trigger
frames; leg 1 (non-trigger suppression) still holds for everything else.

## 4. Blast radius

V1 mechanism (unchanged, restated with grounding method):

| Item | Number | Source |
| --- | --- | --- |
| Mechanism merge b71c52d60 | 33 files, +7043/-360 | git show --stat (STEP-0 lane; re-verify in lab lane, B could not re-verify in-lane) |
| Rust D11 bridge 957b37f4c (pre-squash) | 8 files, +520/-43 | git show --stat; file list matches docs/log/9506-mech.md:23 |
| Live D11 symbol span | 10 files: pipeline.go, reinject_socket.go, pipeline_9506_test.go, reinject_socket_9506_test.go, slowpath.rs, slowpath_reinject_9506.rs, slowpath_reinject_9506_tests.rs, ipsec_inner.rs, ipsec_inner_queue.rs, worker/loop_body/mod.rs | grep pattern `IpsecInnerVerdict\|resolve_ipsec_inner_verdict\|submit_ipsec_inner_v1\|IpsecInnerWorkerTransport\|CompletionWouldPermit\|V1PermitSuppressed` over pkg/nfqueue + pkg/daemon + userspace-dp/src |
| S9.5 code | 0 files; 4 production comment sites + 1 test pin | section 3 |
| Proof script test/incus/t12-g2-9506.sh | 2347 lines, 30 ledger rows, 0 D11-specific cells (grep -ci d11: no hits) | wc + grep |
| Fixture helper test/incus/ipsec-9506-fixture.sh | 1054 lines; setup chain rg_record -> rg_failover(2->node1) -> wait_outer_paths -> peer_up -> gen_config -> commit_file -> install_inner_routes -> converge -> queue-witness | read :856-929 |
| Attempt-2 failure point | fix9506_setup rg_failover step (:887) via firewall RPC | 9506-mech.md:95-100 |
| Unconditional VOID measurement cells on base | fence_shape, divert_order, no_bypass, vrf_refusal, coexistence_order, provenance_metadata (verdict-flip-owned-by-v-flip), ifindex_recreate, bridge_conformance, l2_refusal, rotation_atomicity, integration_ownership, pf_bind_scope, all G2 workload cells (verdict-flip-unimplemented) | t12-g2-9506.sh:2125-2283 |

V2 implementation blast radius (NEW work this plan designs; no S9.5 cutover,
no product semantic change to default paths):

| Ownership point | Files (existing anchors; NEW code marked) | Tests |
| --- | --- | --- |
| Go trigger seam | NEW pkg/nfqueue/pipeline_attest_10484.go: guarded `AttestSubmit` helper, called only by a NEW `dispatchAttestEligible` seam inserted at pipeline.go:462-464 immediately before `submitEligible`; marker selection reads captured `frame.Packet.Payload()` from `eligibleLocked` heads (:529-545), never scans `p.flows` later and never accepts caller bytes; daemon arm callback is in the ipsec_capture_wiring_9506.go authority region (Slice-1 freezes the exact callback line) | default-off (no arm flag -> errAttestDisabled, zero behavior delta, existing suites green); marker heads withheld from routine suppression while armed; one-shot arm (second arm rejected; run/generation-bound); captured-frame-only (raw bytes / non-NFQUEUE frame rejected); pending cleanup on timeout (Poll :848-869), revoke (Cancel :1014-1138), restart (authority reset); trigger-removal census (only consumeFrames seam + arm wiring references) |
| Rust provenance + authority | slowpath_reinject_9506.rs: internal admit-time digest witness (bytes available at :847-920), terminalize row+reason (:1359-1425), terminal tombstones (NEW set in CoreInner :608-621), run_id reset extension (:352-362) | harness independently recomputes and compares the digest; tombstone reuse refused; provenance cap/eviction (PROVENANCE_MAX=128 :498) manifest-size guard; additive status exposure compat (existing chain slowpath.rs:1483-1484 -> coordinator/status.rs:934-940 -> helpers/status.rs:547) |
| Metrics/witness export | pkg/api/server.go:101-120 witness +2 fields (NEW); pkg/api/metrics_ipsec_capture_10478.go:14-59 collector +2; pkg/api/metrics_descriptors_controlplane.go descs +2; pkg/daemon/daemon_run_servers.go:709 callback feeds them; daemon DenyEventSink wiring (NEW counting sink; today zero production setters) | descriptor coverage test extends metrics_ipsec_capture_10478_test.go pattern; unavailable-omitted preserved (:19-21) |
| Management/status RPC | proto/xpf/v1/xpf.proto + generated BpfrxService: NEW GetD11AttestationLedger and bounded D11LedgerRecord schema; authz adds a PermMaint method entry plus a reviewed `methodsWithoutCanonicalCommand` reason because this is a privileged diagnostic, and the handler requires UID 0/superuser server-derived peer-UID principal (not a generic maintenance class); daemon-owned final snapshot remains after runtime reset | generated RPC client polls fw0/fw1 with stable snapshot_seq, exact run_id, finalized/no-truncation gates; non-privileged-principal denial, UID-0/configured-superuser allow cases, method-table completeness, and cap/truncation selftests |
| Script mode + driver | t12-g2-9506.sh: --d11-reattest case (:19-33), D11 buffer branch before replay (:2327), T12_D11_SUMMARY (distinct from T12_G2_SUMMARY :2342), minimal v4_native x2 fixture via fix9506_setup/teardown, shared restore proof | --selftest hermetic trigger/attribution/shape/refusal cases + no-arg regression pin (still 30 rows, exit 2 on VOID) |

Gate: DESIGN (recorded 2026-09-22, re-affirmed in v2). Mechanical is refused
for three independent reasons, any one sufficient: (a) acceptance is a
live-cluster PASS ledger and the design lane cannot run cluster commands; (b)
no mechanical source defect exists -- attempt-2 was environmental (cluster
userspace unarmed), the script already refuses conservatively, and Go
suppression is intentional per the merge-gate ruling; (c) the D11 join
measurement does not exist anywhere (zero D11 cells; verdict-flip observers
unimplemented) AND the trigger authority/permit contradiction (section 5) plus
the missing provenance digest (section 6) require designed contracts, not a
bounded fix. Un-darkening Go submission without the S9.5 safety case would
violate the ruling both reviewers relied on.

## 5. Attestation authority + guarded trigger seam (contract freeze)

V1's central impossibility (reviewer B-F1, adopted): the trigger required
permit CLOSED while reusing lease mint + Rust admission that both require
OPEN. Go MintLease fails closed unless the supervisor record is OPEN
(pkg/daemon/ipsec_capture_pipeline_9506.go:500-517, gate at :504-506); Rust
`allows` requires authority.open (slowpath_reinject_9506.rs:419-427); V1
submit calls admit_with_class first (slowpath.rs:1275-1280), so a CLOSED
permit yields ADMIT_STALE (:880-885) before any D11 work. V1 also invented a
`P-MECH admission DENY_ONLY` constant that has zero source hits. V2 replaces
all of that with the contract below. Slice-1 freezes every NEW detail with
file:line; until frozen, Q1 is mechanism-located, not resolved.

### 5.1 The two permits (never conflate again)

- P1 (S5 supervisor/Rust announce authority): permission to ADMIT leased frames
  and terminalize Deny/WouldPermit completions. States CLOSING/OPEN/CLOSED
  (ipsec_reinject_supervisor.go:27-46). OPEN is reached only via tryOpenPermit
  (:342-366: expected CLOSING + SAFE close key + watch generation match +
  permitEpoch+1 CAS). Revocation via revokeTransitPermitNonblocking (:260-299)
  and finalizePermitClose (:321-340). Rust mirrors it: publish_announce
  (:341-389: run_id/generation/permit_epoch/permit_open/queue_epochs),
  allows (:419-427: open + nonzero epochs + epoch match + tombstone miss +
  queue-epoch match), close_permit (:408-416), queue tombstones (:390-396).
- P1 is not an ordinary S9.5 permit. The attestation authority namespace is
  the NEW `D11_ATTEST` run-id prefix: `run_id=attest-<nonce>` is stored in
  AuthorityState and is the sole attestation selector. The existing ANNOUNCE
  wire has no class field and remains unchanged, carrying exactly
  run_id/generation/permit_epoch/permit_open/queue_epochs. The NEW trigger
  accepts only an exact `attest-<nonce>` authority run; an ordinary transit
  lease with another run_id cannot satisfy that gate. There is deliberately no
  claim that an untrusted local process cannot forge the same namespace; the
  honest server-derived peer-UID trust boundary is in section 6.2.
- P2 (S9.5 permit arm): code-absent. No session install, flow-cache publish,
  NAT mutation, q0 enqueue, or NF_ACCEPT is reachable from the V1 path
  (ipsec_inner.rs:280-288; slowpath.rs:1270-1273 "V1 never enters q0 and never
  asks Rust to permit a frame"). q0 writes additionally require
  TransferVerdict::Written via the pre-write path; V1 verdicts map only to
  Denied/WouldPermit/Uncertain (resolve_ipsec_inner_verdict :1028-1057;
  decide_resolve :456-471), so P1-OPEN can never produce a q0 commit for a V1
  frame even while authority is open.

The lab run OPENS P1 in the `D11_ATTEST` run-id namespace (lab-only,
rollback-specified below) while P2 stays CLOSED by construction (there is no
P2 code to open). Any design that needs P2 is Option C and a PLAN-KILL trigger
(section 8).
- Run binding: the attestation run uses run_id `attest-<nonce>` (NEW convention;
  nonce is exactly 128 bits rendered as lowercase hex, generated by the harness
  pre-run, recorded in the manifest and ledger header). Rust stores run_id
  (:377), and the frame digest (section 6) mixes the stored run_id, binding
  every admitted frame to this exact authority namespace. A concurrent or
  replayed announce with a different run_id resets authority (:352-362) and
  invalidates the run -> VOID, never a mixed-run PASS.

### 5.2 Lab-only OPEN authority (exact wire + gates + ordering)

- ANNOUNCE wire (existing, reused unchanged): Go
  `SocketReinjectSubmitter.AnnounceReinject(runID, generation, permitEpoch,
  permitOpen, epochs)` (reinject_socket.go:245-281; validation :249-260;
  replay-on-reconnect :105-110) encodes exactly
  run_id/generation/permit_epoch/permit_open/queue_epochs
  (`encodeAnnounce` :309-345). Daemon publishes from
  `authoritySnapshot` + `announceAuthorityLocked`
  (ipsec_capture_wiring_9506.go:557-612; dedup :596-600; permitOpen =
  state==OPEN at :581). Rust adopts via `publish_announce` (:341-389),
  including the run_id-change reset (:352-362).
- Publication owner and lock contract (NEW; closes the namespace gap without
  recursion): `ArmD11` is not merely local pipeline state. Use the existing
  runtime `authorityMu` (used by `lockIpsecCaptureAuthority`) and add
  `attestAuthorityOverride`. Define
  `authoritySnapshotLocked` as the internal helper that reads the override or
  normal actor status; the externally callable `authoritySnapshot` wrapper
  acquires `authorityMu` once and calls that helper. Conversely,
  `announceAuthorityLocked` requires `authorityMu` already held and calls
  `authoritySnapshotLocked` directly, never the locking wrapper. Arm,
  reconciliation, reconnect replay, and rollback each acquire `authorityMu`
  exactly once before installing/reading/clearing the override and invoking
  `announceAuthorityLocked`; no caller takes it twice. While active, the
  locked helper returns/replays the override's `run_id=attest-<nonce>`,
  generation, permit epoch, OPEN bit, and queue rows instead of allowing
  actor.Status().RunID or a normal refresh to overwrite it.
- After P1 is already OPEN, the arm callback first reserves ARMING, then holds
  `authorityMu`, installs the override, calls the existing connected client's
  `AnnounceReinject` through `announceAuthorityLocked`, and records the
  announced tuple. It publishes ARMED before unlocking; dispatch refuses all
  trigger heads until that state is visible. The same run nonce/manifest
  binding is installed independently on fw0 and fw1 (with node-local permit
  epochs). Any announce failure clears the override, re-announces normal
  authority under the same lock, records the nonce VOID, and never exposes
  ARMED; reconnect uses the existing replay path, never a second socket.
- Run binding: the attestation run uses run_id `attest-<nonce>` (NEW convention;
  nonce is exactly 128 bits rendered as lowercase hex, generated by the harness
  pre-run, recorded in the manifest and ledger header). The `attest-` namespace
  is the attestation gate; Rust stores run_id (:377), and the frame digest
  (section 6) mixes the stored run_id, binding every admitted frame to this
  exact authority namespace. A concurrent or replayed announce with a different
  run_id resets authority (:352-362) and invalidates the run -> VOID, never a
  mixed-run PASS.
- Eligibility route, trigger frames ONLY: `submitEligible` (:632-715) remains
  unchanged for ordinary frames. The NEW `dispatchAttestEligible` call is
  inserted at `consumeFrames` :462-464, before `submitEligible`: it partitions
  the just-built enforcing slice by the exact captured marker, sends matching
  heads to `AttestSubmit`, and sends every other frame through the existing
  :706-712 suppression arm. The trigger reuses the same zone-gate checks
  (DefaultZoneEvaluator.Evaluate :1227-1248 plus
  validateCapturedGenerations :1251-1279, requiring ZonePass/
  ZoneReasonZoned) and the exact `attest-` authority namespace. No flag is
  threaded through ordinary `submitEligible`; the default path diff is zero.
- Supervisor transition (lab-only): on the isolated loss cluster under the
  with-cluster lock, the fixture-built SAFE topology lets tryOpenPermit advance
  CLOSING->OPEN with permitEpoch+1 (:358-364). Slice-1 records the exact
  preconditions observed (SAFE close key contents, watch generation) and pins
  whether the lab uses the normal topology-driven path or a lab-only opener;
  either way, this transition is what existing MintLease (:504-506) and Rust
  allows (:419-427) check before the override publishes OPEN.
- Rollback ordering (exact existing-owner ordering plus one close ACK hook):
  (1) reject new arm and disarm triggers; (2) scoped `CancelReinject` for the
  lab permit epoch/queue scopes (`Cancel` :1014-1138; submitGate write lock
  :1018 linearizes against in-flight submits); (3) drain completions via Poll
  (:828-847) until pending empty and verify `p.pending`/every `flow.pending`
  are empty; (4) under the with-cluster rollback exclusion and the existing
  apply-semaphore owner, capture `expectedOpen := supervisor.loadPermit()` and
  require it is OPEN, then call the existing
  `retireHostInputFenceOverlay(cfg, expectedOpen)` (:242-283) before revoking.
  Its old-set conntrack ACK plus empty-candidate nft/readback is the only
  accepted fence retirement, and the concurrent-authority check must pass
  (the test contract :261-263). Never use `reconcileIpsecHostInputFence` for
  this close step: its CLOSING branch can call
  `tryOpenIpsecPermitAfterFenceAck` (:153-156, :208/:213/:242). A retirement
  error is VOID and blocks every later step. (5) while the existing submitter
  remains connected, Rust `close_permit` (:408-416) and tombstone lab queue
  epochs (:390-396), so no further admission can cross the close; (6) under
  the same exclusion, revoke each active topology permit with
  `revokeTransitPermitNonblocking` (:260-299), leaving Go CLOSING; (7) hand
  teardown to `ipsecCaptureRuntime.close` (:626-667), which stops
  listeners/actors, closes queues and the submitter, and retires queue
  handles, and wait for its positive ACK; (8) only after those
  gates/listeners/queue-destruction/fence ACKs does the S4 close coordinator
  (NEW call at the existing owner boundary) take `drainCommitLeases`
  (:304-314) and invoke `finalizePermitClose` (:316-340). Direct
  trigger-side finalization is forbidden. Slice-1 pins a unit transition test
  OPEN fence-retire ACK -> revoke/CLOSING -> no reopen arm -> finalizable.
  Verify `supervisor.loadPermit` is CLOSED before changing authority identity.
  (9) under `authorityMu`, clear `attestAuthorityOverride`; restore/recreate
  the capture runtime through the existing stage/restore/publish owner
  (:1050-1098) and have that normal CLOSED runtime announce
  `permit_open=false` (:363-369) on its connected submitter. (10) verify
  Rust `authority.open=false` (:1341), Go CLOSED state, arm disarmed, and the
  shared restore/residue proof before any ledger emission. Any failed step is
  VOID; a PASS row before step 10 is FAIL.
### 5.3 Guarded trigger seam (NEW; Slice-1 freezes, Slice-2a builds)

- Control arm (one exact shape; no alternatives): each daemon must have
  `XPF_ATTEST_10484_ARM=1` in its process-start environment. The lab driver
  sends that same action grammar independently to fw0 and fw1 through the
  existing loopback gRPC `SystemAction` path
  (pkg/grpcapi/server_diag_system_action.go:380-504):
  `userspace-attest:arm:<run_id>:<permit_epoch>:<manifest_count>:<marker_hex>`.
  The run_id/nonce are common to the manifest; each daemon supplies its
  locally observed supervisor `permit_epoch`, and `manifest_count`/`marker_hex`
  are node-local entries (Q3 is RG1/even on fw0 and RG2/odd on fw1). The
  manifest partitions lease identity by node, and the ledger binds both
  partitions to the same nonce. Each daemon wires that action to a NEW
  `D11AttestationArmer` callback in its ipsec_capture_wiring_9506.go authority
  region. Existing SystemAction authorization must require a server-derived
  peer UID of 0 or a configured superuser for this prefix-form action;
  `PermMaint` alone is insufficient because the current command gate rejects
  restricted classes with no canonical resolver
  (authz_command_gate_7172.go:77-82, :113-117). Before mutation, reject a
  missing arm environment, a principal that is neither UID 0 nor a configured
  superuser, malformed run/nonce, manifest_count outside 1..32, marker
  encoding error, absent local D11 wiring or authority snapshot, or an
  already-active run.
  There is no node-wide "primary" rejection: RG ownership is checked per
  marker below, because RG1/fw0 and RG2/fw1 both participate. The action is an
  arm request only; it does not dial either reinject socket.
- One-shot and nonce binding: `ArmD11` stores
  `(node_id, run_id, nonce, local_permit_epoch, marker, manifest_count)` and
  atomically reserves `INACTIVE -> ARMING`; `dispatchAttestEligible` accepts
  no marker while the state is ARMING. The armer then holds `authorityMu`,
  installs the attestation override, and successfully calls the existing
  `AnnounceReinject` path. While still holding that lock, it publishes
  `ARMED`; dispatch accepts trigger heads only in ARMED. If announce fails,
  it clears the override, re-announces normal authority under the same lock,
  records the nonce VOID, and returns to INACTIVE without ever exposing ARMED.
  A second arm for the same node/run/epoch pair, or any different pair while
  one is active, is rejected. The ARMED run may consume at most
  `manifest_count` distinct marker heads; per-head request IDs are unique and
  terminalized once. Disarm is irreversible for that run and is allowed only
  after the rollback drain; a same-nonce re-arm is refused until daemon
  restart. The manifest nonce, ANNOUNCE run-id suffix, exact `attest-`
  authority namespace, digest run mix-in, and marker prefix must all agree;
  mismatch is VOID and never submits.
- Node/RG ownership is per selected frame, not a node-wide primary bit:
  fw0 must accept the RG1/active-owner markers and fw1 the RG2/active-owner
  markers (Q3 sends both). `dispatchAttestEligible` and `AttestSubmit` verify
  the captured origin/STN, queue, and local authority snapshot against that
  node's active RG; a marker presented to the wrong node/owner is a named VOID
  and is never silently skipped or sent through routine suppression.
- Dual-node readiness gate: the driver polls both local armer statuses and
  both Rust authority snapshots, and sends marker traffic only after fw0 and
  fw1 are ARMED with their node-local permit epochs and the common
  `attest-<nonce>` run_id announced. Either node still ARMING, CLOSED, or
  namespace-drifted makes the run VOID; no marker is counted from a
  one-node-ready window.
- Stable interception point (the V1 selector fix): the current
  `consumeFrames` path obtains eligible heads and sends every enforcing head to
  `submitEligible` at pipeline.go:462-464. Replace only that call site with
  NEW `dispatchAttestEligible`: while the `Drain` caller still holds
  `drainMu` (:403-417), it partitions the just-built enforcing slice into
  `(attest, ordinary)` using `eligibleLocked` heads (:529-545) and the exact
  captured bytes from `Packet.Payload()` (nfqueue.go:373-427). It MUST NOT
  scan `p.flows` from a later control call, accept a raw-byte argument, or
  select an already-consumed frame. An armed, exact-marker head is removed
  from `ordinary` and sent to `AttestSubmit` before ordinary
  `submitEligible`; an unrelated non-marker, unarmed frame, or marker that is
  not this node's exact marker stays in `ordinary` and reaches the existing
  suppression arm unchanged. An exact-marker head with wrong origin/STN/RG
  ownership is instead a selected D11 row and becomes the named VOID from the
  preceding bullet; it is never silently routed through suppression.
- Withholding and reservation: `dispatchAttestEligible` acquires
  `submitGate.RLock`, takes `p.mu` only to partition/reserve, and sets each
  selected flow's `pending` pointer plus `p.pending[request_id]` before it
  releases `p.mu` or calls the socket. Because `Drain` holds `drainMu` across
  this whole dispatch and `flow.pending != nil` excludes a head from
  `eligibleLocked`, routine suppression cannot delete a selected marker or race
  it into a second batch. A validation or lease refusal before reservation
  terminal-drops the marker and marks the D11 row VOID; it does not increment
  routine `V1PermitSuppressed`.
- `AttestSubmit` is an internal helper with no arbitrary-frame caller; it is
  reachable only from `dispatchAttestEligible` and receives frames selected
  from this consume pass. It factors the current L2, zone evaluator,
  `validateCapturedGenerations` (:1251-1279), and `ValidateZoneEvaluation`
  (:1281-1288) checks out of `submitEligible` so both paths use the same
  predicates. It then calls NEW `MintLeaseForAttest`, a wrapper around the
  existing lease allocator that requires the exact `attest-<nonce>` authority
  namespace and permit epoch but adds no lease class field or submit-wire flag;
  it builds `AdjudicatedFrame`s with the same fixed wire shape. `p.mu` is
  released before `SubmitAdjudicated` performs network I/O;
  `submitGate.RLock` remains held through the call so `Cancel`'s write lock
  linearizes revocation.
- Lock order is explicit: `Drain` `drainMu` -> `submitGate.RLock` ->
  `p.mu` (reservation only) -> submitter `submitMu` (inside
  `SubmitAdjudicated`). No `p.mu` is held while acquiring `submitMu`, and no
  path takes `p.mu` then `submitGate`; `Cancel` is
  `drainMu -> submitGate.Lock -> p.mu` (:1016-1019), `resolveCompletion`
  takes `p.mu` only (:925-970), and Poll does not hold pipeline locks around
  completion drain (:828-847). The route therefore cannot recreate the
  selector race or deadlock the existing cancellation/completion paths.
- Admission and pending lifecycle: call `SubmitAdjudicated` once for the
  selected batch. Match every `ReinjectAdmission` by
  `(node_id, request_id, local lease tuple)`: ADMIT_OK waits for a completion;
  STALE/FULL/BAD_LEASE/SHUTDOWN/
  BRIDGE/INPUT_HOOK/NON_DRY_RUN/NO_GENERATION/TUNNEL_ROW_MISSING (codes
  slowpath_reinject_9506.rs:41-50; checks :868-892) delete the pending entry,
  clear `flow.pending`, retire an empty flow, increment
  `AdmissionsRefused` and `Stale` for STALE, and record the named gap. A
  transport/decode error cancels all request IDs by queue scope, clears
  pending, and marks them Uncertain. Any refusal is pre-join -> VOID, never a
  retry into PASS. A completion resolves through the existing Poll/resolve
  path; timeout, revoke, helper restart, or authority drift follows
  Poll (:848-869) / Cancel (:1014-1138) cleanup and cannot reselect a head.
- Singleton and socket rule: the Rust accept loops
  (submit :317-340, complete :343-362; comment :360-361) document one
  completion client but do not enforce ownership. The existing single Go
  `SocketReinjectSubmitter` instance is therefore the singleton by
  construction; no second drainer, announcer, direct socket client, or
  companion control socket is added. The trigger control action uses the
  existing gRPC management surface, while data uses only the already-connected
  client's `SubmitAdjudicated` (:115-147), `DrainReinjectCompletions`
  (:149-197), and `CancelReinject` (:200-222).
- Rollback delegates to the §5.2 owner sequence; the trigger only requests
  it and never calls `finalizePermitClose` or `reconcileIpsecHostInputFence`:
  (1) reject new arm/disarm; (2) scoped `CancelReinject`; (3) Poll until
  pending empty and verify `p.pending`/every `flow.pending` empty; (4) while
  OPEN, `retireHostInputFenceOverlay(cfg, expectedOpen)` supplies the
  conntrack/nft fence-retire ACK; (5) Rust close/tombstone while submitter
  connected; (6) topology revoke leaves Go CLOSING; (7)
  `ipsecCaptureRuntime.close` stops actors, closes queues/listener resources,
  and retires handles; (8) the S4 close owner drains commit leases and
  finalizes CLOSED; (9) observe Go CLOSED, then clear the override under
  `authorityMu` exactly once, restore/recreate the runtime, and announce
  normal CLOSED; (10) verify Rust CLOSED, Go CLOSED, arm disarmed, and shared
  restore/residue before ledger emission. Any failed step is VOID; a PASS row
  before the final proof is FAIL.

- Deny-only predicate table (each row cites the enforcing code, not an
  assertion): zone pass (Evaluate :1227-1248 + validateCapturedGenerations
  :1251-1279); NEW attestation lease needs P1-OPEN and the exact
  `attest-<nonce>` authority namespace (supervisor transition :342-366;
  Rust allows :419-427); V1 verdicts map to Denied/WouldPermit/Uncertain only
  (:1028-1057 + decide_resolve :456-471; Written unreachable without the
  pre-write path); Go terminal drops every completion (:971-990 all arms
  finishFrame(DROP)); q0/session/NAT/NF_ACCEPT absent
  (ipsec_inner.rs:280-288; slowpath.rs:1270-1273). Slice-1 re-verifies each
  row at the run commit; any row that no longer holds is PLAN-KILL, not a
  waiver.
## 6. Resolved questions, provenance design, and test predicates

### 6.1 E28 split (binding fix A-P0-1/B-F2; V1 predicate was impossible)

V1 required "outcome-10 maps to V1PermitSuppressed, never E28; E28 byte-52
stays zero". Source contradicts it on the Go side: terminal WouldPermit
increments V1PermitSuppressed (:964-965) AND emits deny-52 (:983-984,
ReasonEvaluatorUnavailable=52 at :1316, Valid() :1327-1328) through the sink
(:569-581) whenever a sink is configured; the comment at :101-103 states the
terminal mapping explicitly and distinguishes it from routine suppression
(:706-712, no emitDeny call) which emits nothing. The D11 cells exercise the
TERMINAL path, so Go-52-zero cannot hold on any passing run. The Rust comment
(ipsec_inner.rs:284-286 "It is NOT E28") describes the Rust verdict half only.
V2 splits the predicate (deltas sampled around the trigger window; absolute
counters are never asserted because zone-gate 52s at submitEligible :653-660
and worker admit paths pollute globals):

- Rust-52-delta == 0 across D11 verdicts. WouldPermit carries no reason
  (ipsec_inner_queue.rs:190-192); reason 52 = EVALUATOR_UNAVAILABLE (:75;
  E-row 28 -> 52 at :119) signals evaluator/snapshot/worker-set failure
  (D14 arms ipsec_inner.rs:190-193,270-271). Observation: NEW `reason: u8`
  field on ReinjectProvenanceRow (Slice-2b; WouldPermit rows carry 0). Any D11
  row with reason==52, or any expected-WouldPermit frame terminalizing
  otherwise, is FAIL. Until the field exists, this cell is VOID (never
  inferred from global counters).
- Go-52-delta == WouldPermit-count (1:1, delta over the trigger window) AND
  V1PermitSuppressed-delta == WouldPermit-count. Observation: NEW metrics
  xpf_ipsec_capture_suppressed_total + xpf_ipsec_capture_deny_events_total
  {reason} via witness extension (Slice-2c; required because production sets
  no DenyEvents sink today -- zero setters in pkg/daemon -- so emitDeny at
  :569-572 is currently a no-op in production and Go-52 is unobservable).
  Until wired, this cell is VOID. Requiring Go-52 zero would invert designed
  deny-only observability; removing :984 to satisfy it would be a product
  semantic change and is out of scope (its own safety case, not this plan).

### 6.2 Provenance digest, Go join ledger, and trust model (binding fix A-P0-3/B-F3)

The digest/marker field does not exist: ReinjectProvenanceRow
(:500-513) carries request_id/permit_epoch/queue_epoch/queue_number/family/
hook/owned_ifindex/owner/stn/outcome/bytes_written -- bytes_written is a
count, not a content binding. Entry (:599-606) retains lease/origin/flow_tag/
connection_id/since/state; SubmitFrame.bytes (:167-172) is dropped after admit
(worker sees descriptor fields with inner_packet=&[], loop_body:731-733). The
status chain (status_snapshot :1322-1347, None unless run_id+generation set at
:1324-1326; slowpath.rs:1483-1484; coordinator/status.rs:934-940;
helpers/status.rs:547) exposes rows as-is with PROVENANCE_MAX=128 evict-oldest
(:498, :1404-1408). Trust today is peercred root-or-self
(userspace-dp/src/server/lifecycle.rs:196-262) + 0600 mode (:174-178);
handlers are unauthenticated (:188-191, :257-258). Any root process can submit
and can announce a new run_id (:352-362 resets authority); replay is unstopped
after ack (:1187) and cancel (:1246) remove entries (only queue-epoch
tombstones exist at :390-396; the live-id duplicate check at :886-887 covers
live ids only). V1's `authenticated` wording therefore overclaimed. V2 design
(NEW, Slice-1 freezes, Slice-2b builds):

- Rust witness, not an admission input: add `frame_digest: [u8;32]` and
  `reason: u8` to `ReinjectProvenanceRow`. The entry retains the computed
  digest internally until terminalization; no expected digest is added to
  SubmitFrame or the existing submit wire. At `admit_with_class`
  (:847-920), where the submitted bytes are present, hash canonical
  bytes || lease(request_id/permit_epoch/queue_epoch/queue_number) ||
  origin(family/hook/owned_ifindex/owner/stn) || the stored
  `authority.run_id` using one pinned algorithm (SHA-256 or BLAKE3, with a
  Cargo cite frozen in Slice-1). This is an admit-time witness, not a
  self-comparison and not an ADMIT_BAD_LEASE gate. `terminalize`
  (:1359-1425) copies the retained digest and reason into the row; status
  exposure reuses the existing chain with additive JSON fields (Slice-2b
  records wire-compat impact + test).
- Independent harness comparison: the manifest stores the exact captured bytes,
  node_id, local lease tuple (including that node's observed permit_epoch),
  origin, and announced common `attest-<nonce>` run_id. The D11 driver
  independently computes the same canonical digest and compares it with the
  Rust provenance row for the same `(node_id, request_id, local lease tuple)`.
  Missing row, missing digest, or mismatch is FAIL; unavailable status is VOID.
  A bad harness computation cannot cause Rust to refuse a valid frame, while a
  Rust bug or a harness misjoin is still observable as a failed comparison.
- NEW bounded Go join ledger with a concrete readable surface: keep a
  daemon-owned, run-scoped `D11AttestationLedger` (not a field of the capture
  runtime, not `IpsecCaptureWitness`, and not Prometheus), capped at
  `manifest_count` (1..32). Runtime stop, authority override clear, Rust
  run-id reset, and capture restore/recreate MUST NOT clear it. The ledger
  remains queryable after rollback with its final snapshot; only a later
  explicit `ArmD11` for a new nonce may replace/clear the prior finalized
  ledger, after the driver has archived that final RPC artifact. Add the NEW
  unary gRPC method
  `GetD11AttestationLedger(GetD11AttestationLedgerRequest) returns
  (GetD11AttestationLedgerResponse)` to `proto/xpf/v1/xpf.proto` and its
  generated service. The response is a bounded, single-snapshot object:
  `run_id`, `node_id`, local `permit_epoch`, `snapshot_seq`, `finalized`,
  `truncated`, and repeated `D11LedgerRecord` (never paginated). Each record
  contains node_id, request_id, local lease tuple
  (permit_epoch/queue_epoch/queue_number), origin
  (family/hook/owned_ifindex/owner/stn), frame_digest bytes[32], admission
  code, completion outcome, `resolve_count`, `terminal_state`, and
  `late_attempts`. A cap overflow sets `truncated=true` and makes the run
  VOID; a non-final snapshot is not accepted as the rollback artifact.
- The new RPC is read-only but is authorized by the existing gRPC
  interceptors at a NEW `PermMaint` method entry plus a reviewed
  `methodsWithoutCanonicalCommand` reason (it has no ordinary CLI command).
  The handler then requires a server-derived peer UID of 0 or a configured
  superuser, exactly like the arm; the AF_INET loopback listener derives it
  from `/proc/net/tcp{,6}` because `SO_PEERCRED` is unavailable
  (`pkg/grpcapi/README.md:170-179`). `PermMaint` alone is insufficient because
  restricted classes would hit the unmapped-method deny at
  authz_command_gate_7172.go:113-117.
  Remote/unprivileged requests are denied. The D11 driver reads this generated
  RPC over the existing loopback management channel on fw0 and fw1 after each
  poll and once after rollback, authenticating as root/superuser. It requires
  a stable `snapshot_seq`, exact `run_id`, `finalized=true` for the final
  artifact, and no truncation before comparing
  `admitted == completed == manifest`; it never reconstructs a composite-key
  join from aggregate Prometheus counters.
- Each composite key `(node_id, request_id, local lease tuple)` record
  contains the captured origin, the independently recorded frame_digest,
  admission code, completion outcome, `resolve_count`, and terminal state.
  Record the admission response
  before admitting it to the live set; update the record on every completion
  attempt, including duplicate/late attempts, and publish the final
  `resolveCompletion` outcome rather than leaving the bool internal. If the
  cap is exceeded, a request is missing, or a second terminal transition is
  observed, the run is VOID/FAIL per section 6.4. Ledger publication is
  synchronized with pipeline terminalization; rollback marks the ledger
  finalized but never clears it, so the post-rollback RPC remains the
  acceptance artifact until the next explicit arm replaces it.
- Run binding + replay window: run_id `attest-<nonce>` stored at publish
  (:377); the Rust digest mixes it, so the harness comparison rejects a
  cross-run misjoin. NEW terminal tombstones: BTreeSet<u64> in CoreInner
  (:608-621), inserted at terminalize, consulted at admit (member ->
  ADMIT_BAD_LEASE), cleared ONLY on the run_id-change reset path (:352-362,
  extended). Go request_ids are already monotonic per actor
  (requestID.Add(1) :512-515). Manifest set equality and the Go ledger close
  the loop harness-side.
- Honest trust statement: the covered threat model is a trusted lab pair with
  server-derived peer-UID-gated privileged-local callers (UID 0 or a
  configured superuser). It detects
  implementation bug-misjoins (the independent Rust digest comparison and Go
  per-key ledger disagree on the wrong frame/id) and replay (tombstones plus
  run binding). It does NOT cover a malicious root/daemon-user on the firewall
  (the Rust 0600 root-or-self endpoint already permits submit/announce/read);
  a configured superuser is trusted by the NEW Go arm/ledger gate and is not
  treated as malicious in this scope. There is no per-row MAC, nonce challenge
  beyond run binding, or freshness beyond run scope. The cells prove join
  integrity against implementation bugs on a trusted lab pair, nothing stronger.
  Slice-1 records this verbatim; any v2 sentence still saying bare `authenticated` is a defect.
- PLAN-KILL (narrowed): if the digest witness cannot be generated at the Rust
  admit point and independently exposed for harness comparison, or the
  run-scoped Go ledger cannot expose one authoritative record per
  `(node_id, request_id, local lease tuple)` (admission, completion outcome,
  resolve count, terminal state) through the authenticated
  `GetD11AttestationLedger` RPC, sequencing returns to the owner. Missing
  witness stays fail-closed: VOID, never inferred.

### 6.3 Q1-Q5 (all re-grounded; Q1 is mechanism-located until Slice-1 freezes)

- Q1 (join observability): MECHANISM LOCATED. Pending gate (:925-936) +
  lease/bytes checks (:937-943) + terminal arms (:953-990) verified; trigger
  insertion protocol + lock order + ADMIT handling specified in section 5.3.
  Slice-1 freezes the remaining NEW details (arming shape, census test,
  close-owner transition, and authenticated Go-ledger RPC); the word
  `resolved` must not reappear until that freeze lands.
- Q2 (26B tail contract): RESOLVABLE with exact cites. Go builder
  `encodeSubmitBatch` (reinject_socket.go:348-391; flags byte 0 at :375;
  flowTag(FlowKey) at :374; tail Snapshot8+Config8+FIB4+Zone2+IfID4 at
  :385-389; len 26 at :33) + TestEncodeSubmitBatchPMechTailTwoFrames9506.
  Rust strict decoder (decode_submit_batch :1561-1635: BadFlags :1575-1577
  unless SHADOW|DRY_RUN; FrameTooLarge :1597-1599; TrailingBytes :1631-1633)
  + tail len 26 (:28). Live flags: 0 only (DRY_RUN refused at admit :861-867
  and at submit_adjudicated_frame slowpath.rs:1325-1329). Generations
  post-#10485: captured on the frame at capture time, validated two-authority
  Go-side (validateCapturedGenerations :1251-1279: Snapshot vs capture
  authority, Config/FIB vs accepted authority :1217-1219, exact match or
  Stale/Unknown) and triple-exact Rust-side at D14 (ipsec_inner.rs:182-213:
  nonzero, view match, exact STN row, if_id + logical_ifindex match);
  zone_id/if_id derive from ResolveSTN + Evaluate (:1227-1248; ZoneID/IfID
  nonzero required, else VersionSkew at ValidateZoneEvaluation
  pipeline.go:1281-1288). Trigger needs NO separate generation fetch: it
  reuses the gate, so stale frames DROP before submit by construction.
  Slice-1 pins the exact tail bytes + flags + generation window for the run
  commit.
- Q3 (workload shape and binding): v4_native x2 minimum, one even/RG1/fw0 +
  one odd/RG2/fw1 (fixture_probe_indices t12-g2-9506.sh:96-102;
  fixture_measure_traffic :1440-1498; XFRM if_id 0x25220001/2). Every marker
  packet gets a manifest row: node_id, bytes digest, origin, and that node's
  local queue/lease identity and observed permit_epoch; request_id is assigned
  by the trigger at submit. The D11 observer joins on
  `(node_id, request_id, local lease tuple)`, matching origin + digest in the
  Rust provenance row and Go per-node ledger before counting; the ledger must
  also show one admission, one completion, resolve_count==1, and terminal
  state. XFRM deltas corroborate fixture readiness ONLY. Manifest cap: 32
  frames total across both nodes (PROVENANCE_MAX=128 evict-oldest at
  :1404-1408 leaves 4x headroom; quiesce means no concurrent admitters).
  Missing witness/ledger row -> VOID, never infer.
- Q4 (dark-triple re-grounding): REQUIRED with a §8 gate (new in v2). Leg 1
  holds for non-trigger frames (:706-712 unchanged). Legs 2-3 (tunnel-row
  E28-deny at coordinator/mod.rs:1639-1645 + D14 exact gate :182-213) are
  re-grounded row-by-row before the run; trigger frames are admitted only
  after their tunnel rows are populated and generations are aligned, so the
  empty-row E28 gate is not the trigger predicate. This is a bounded
  selection exception, not a claim that the default dark path is broken:
  ordinary/non-trigger frames still take the unchanged suppression arm. If
  re-grounding finds non-trigger submits reachable or any way to bypass leg 1
  without the exact trigger, the result is PLAN-KILL; the trigger must not
  cover for a broken default.
- Q5 (cluster repair ownership): lab operator owns it, with falsifiable
  criteria (new in v2). Order verified against manager_ha TakeoverReady
  (manager_ha.go:403-458): helper enabled (:408-410), ForwardingSupported +
  UnsupportedReasons (:411-417), ForwardingArmed (:418-420), XSK proven
  (:427-429; failed flag :424-426), session mirror (:430-436), snapshot debt
  (:441-445). XSK break-glass: the documented circularity (election.go:877-882:
  proving XSK liveness requires traffic, traffic requires a primary; observed
  live, recovered only when traffic was hand-driven) is broken by hand-driven
  marker traffic + the degraded-promotion fallback contract (:867-904);
  Slice-3 records the verbatim operator commands + expected TakeoverReady
  output per step. Unsupported-vs-unarmed: ForwardingSupported==false with
  non-empty UnsupportedReasons persisting across deploy + 10-minute timeout
  (value owner-confirms in Slice-1) => PLAN-KILL (hardware); not-armed /
  liveness-unproven => retry + traffic-drive, and any D11 cell stays VOID
  until has_st=has_sa=has_divert=1 on both nodes + complete_fixture=1.

### 6.4 Test predicates (per-cell table; q0 witness; FAIL mapping)

Conventions: every predicate is a DELTA over the trigger window (sampled
before/after on the same surface) plus the Go ledger's per-node join equality
on `(node_id, request_id, local lease tuple)`:
`admitted == completed == manifest` with no extra/missing/duplicate key.
Absolute counters are never asserted. Any required surface unavailable ->
VOID with the surface named. Routine-path pollution guard: the trigger window
is quiesced (fixture pings paused except marker packets); any nonzero delta
in routine-only counters (ZoneGateDrops and friends) -> VOID (pollution),
never subtracted out.
| Cell | Proves | Observer (authoritative surface) | VOID if | FAIL if |
| --- | --- | --- | --- | --- |
| d11_9506_submit_admit | trigger + admit + 26B tail/generation acceptance, both nodes | Go D11 ledger admission records keyed by (node_id, request_id, local lease, origin, digest, admission code) plus ADMIT responses per composite key (ADMIT_OK :41) + adjudicated_admitted delta (:1427-1431) | authority drift (STALE), FULL, any refusal code (pre-join -> VOID with code), ledger/status unavailable | duplicate composite key admitted twice (:886-887 bypassed); admitted key outside manifest; ledger record differs from ADMIT |
| d11_9506_worker_verdict | Rust adjudication + transport + terminalization; split Deny/WouldPermit; never q0 | provenance rows keyed by (node_id, request_id, local lease) with outcome split, origin, independent digest + row reasons (NEW fields); q0 primary witness below | rows missing (incl. eviction), reason/digest field absent, observer unavailable | outcome/identity/digest mismatch vs manifest expectation; ANY row reason==52; ANY row outcome==written (Rust half of never-q0) |
| d11_9506_completion_join | end-to-end join, the only true join proof | Go D11 ledger (one admission, one completion outcome, resolve_count==1, terminal state per (node_id, request_id, local lease)) + Rust rows with same key (origin/digest match) + LateCompletions delta==0 (:929) + Timeouts delta==0 (:848-869) | any observer unavailable; completions pending past deadline without terminal state | misjoin (wrong node/id/lease/origin/digest); duplicate terminal; late completion; resolve_count!=1; missing row; Go/Rust outcome disagreement |
| d11_9506_wouldpermit_accounting | suppression accounting split (section 6.1) | Rust row reasons (52-delta==0) + NEW xpf_ipsec_capture_suppressed_total (delta==WouldPermit-count) + NEW xpf_ipsec_capture_deny_events_total{reason=52} (delta==WouldPermit-count) | metrics/sink unwired; reason field absent | Rust-52-delta!=0; Go-52-delta!=count; suppressed-delta!=count; WouldPermit row carrying reason 52 |

- Never-q0 witness (complete): PRIMARY per-key: every manifest
  `(node_id, request_id, local lease tuple)` has a Rust provenance outcome !=
  "written" (:228-242 outcome strings; terminalize mapping :1412-1423) AND a
  Go ledger completion outcome != Written with `resolve_count==1` and terminal
  state. SECONDARY global: completed_written (:1413), Written (:218),
  Reinjected (:232) deltas == 0 over the window. Either half violated -> FAIL.
  Either half unobservable -> VOID.
- Negative controls (hermetic, in --selftest, mirroring cell_verdict
  conservatism at t12-g2-9506.sh:986-1003): mutate manifest bytes before the
  independent digest calculation and require a digest mismatch FAIL (there is
  no Rust refusal based on an expected digest); wrong-lease completion ->
  Uncertain + DROP (:937-947, :971-981); duplicate completion ->
  LateCompletions + resolve false (:928-932); unknown id -> LateCompletions;
  already-terminal second verdict refused (terminalize guard :1366-1402).
  Live run carries no adversarial injection beyond the manifest.
- E28 delta semantics: Rust-52 from NEW row-reason bytes (per composite
  key, no pollution); Go-52 from NEW deny-event metric (per-run window;
  routine 52s from :653-660 etc. are excluded by the quiesce guard, and any
  routine traffic in-window voids the run rather than being subtracted).
- Mode mechanics (exact): add `--d11-reattest` case to arg parse (:19-33);
  D11 branch selects the 4-row buffer BEFORE the replay loop (:2327-2336;
  restore demotion :2329-2334 applies to D11 rows identically -- a PASS
  written before restore is FAIL per section 8); separate gate
  D11_CELL_COUNT==4, pass==4, fail==0, void==0, exit 0; summary
  T12_D11_SUMMARY (new name; must not collide with T12_G2_SUMMARY :2342);
  row-count gate (:2338) untouched for the no-arg path. Fixture: MINIMAL
  v4_native x2 via the SAME fix9506_setup/teardown code path (not the full
  30-row T12+G2 workload: that contradiction is resolved -- shared code,
  minimal shape) + shared restore proof. Selftest regression pin (NEW case):
  no-arg mode still emits exactly 30 rows and exits 2 on VOID.

## 7. Recommended shape (lab lane, not this lane)

Slice 1 -- contract freeze (source-only, no cluster; the load-bearing slice):
  a. Freeze the exact section 5 trigger contract: process-start
     `XPF_ATTEST_10484_ARM=1`; existing loopback gRPC SystemAction
     `userspace-attest:arm:<run_id>:<permit_epoch>:<manifest_count>:<marker_hex>`
     sent independently to fw0 and fw1; server-derived peer UID 0 or
     configured superuser required for both arm and ledger reads
     (prefix-form SystemAction cannot use generic `PermMaint`);
     D11AttestationArmer callback; one-shot
     `(run_id/nonce common, node-local permit_epoch)` binding; per-marker
     RG/origin/STN ownership.
     Pin the authorityMu/authoritySnapshotLocked/announceAuthorityLocked
     lock ownership (no recursive acquisition), the NEW `consumeFrames`
     :462-464 interception before `submitEligible`, captured-byte marker
     selection, zone/lease/admit call sequence with every error arm, the
     deny-only table, and the census test placement. Freeze rollback ordering:
     OPEN `retireHostInputFenceOverlay` ACK before revoke, runtime close,
     queue/listener teardown ACK, S4 close-owner finalization, then normal
     CLOSED re-publication; `reconcileIpsecHostInputFence` is not the close
     primitive. Freeze Q2 tail bytes + flags + generation window, the admit-time
     digest witness and independent harness comparison, and the concrete
     authenticated bounded `GetD11AttestationLedger` RPC schema/retention.
     Freeze metric names and all status/ledger gates. Until every item has
     file:line, Q1 stays mechanism-located.
  b. Verify the D11 unit proofs still pass at the run commit (cargo
     ipsec_inner_queue 18 cells, ipsec_inner_verdict_bridge 2 cells,
     reinject_9506 66 cells; Go AdmissionReasonConsistency /
     SubmitBatchPMechTailTwoFrames / ExtendedCompletionOutcomes) as the
     pre-live gate. Any failure is PLAN-KILL for the run until fixed upstream.
Slice 2 -- guarded trigger + observability + cells (narrow mechanism seam,
NOT script-only; ownership in section 4):
  a. Go trigger seam (NEW pipeline_attest_10484.go + daemon arming): per
     section 5.3. Default-off; explicit auth; one-shot; captured-frame-only;
     per-marker RG ownership; pending protocol; ADMIT_* table; rollback hooks.
  b. Rust provenance diff (slowpath_reinject_9506.rs): internal admit-time
     digest witness + row.frame_digest + row.reason; no expected digest on
     the submit wire and no digest-based admission refusal; terminalize copy;
     terminal tombstones + run-reset extension; status additive fields.
     The harness computes the digest independently and compares the row.
     Missing witness stays VOID/FAIL per section 6.4.
  c. Go observability diff: daemon-owned bounded run-scoped
     `D11AttestationLedger`, keyed by `(node_id, request_id, local lease
     tuple)` and carrying origin/digest, admission code, completion outcome,
     resolve_count, terminal state, and late attempts. Expose it through NEW
     authenticated `GetD11AttestationLedger` in `proto/xpf/v1/xpf.proto` (not
     the scalar `IpsecCaptureWitness`/Prometheus callback); retain the
     finalized snapshot across runtime close/authority reset until a later
     explicit arm replaces it. Also add IpsecCaptureWitness +Suppressed +Deny52
     (server.go:101-120); collector +2 (metrics_ipsec_capture_10478.go:14-59,
     unavailable-omitted preserved); descs +2
     (metrics_descriptors_controlplane.go); daemon callback feeds them
     (daemon_run_servers.go:709); daemon counting DenyEventSink wiring (NEW;
     today zero production setters). Extend descriptor, RPC-auth, and ledger
     coverage tests.
  d. Script mode + driver: --d11-reattest per section 6.4; trigger driver
     (manifest build, marker traffic, counter sampling, set-equality join);
     minimal x2 fixture; shared restore proof; T12_D11_SUMMARY.
  e. Selftest: hermetic trigger-auth/attribution/shape/refusal cases +
     no-arg regression pin. D11 rows default VOID with explicit reasons until
     the live path proves them.
Slice 3 -- cluster repair runbook (operator/lab):
  a. Repair in TakeoverReady order (manager_ha.go:403-458) with verbatim
     commands + expected reasons-output recorded per step: helper enabled ->
     ForwardingSupported (+UnsupportedReasons, empty required) -> ForwardingArmed
     -> XSK proven (break-glass: hand-driven marker traffic per
     election.go:877-882 + degraded-promotion contract :867-904) -> RG2 ready
     (fix9506_rg_failover 2 1) -> fix9506_converge stn=2/2, SA egress/ingress,
     queues, nft=1/1. Unsupported criteria per Q5.
  b. Deploy gate: XPF_DEPLOY_FAST=1 make cluster-deploy from a clean tree at a
     commit containing b71c52d6093f; pre-run executable SHA verification on
     local, fw0, fw1 (attempt-2 procedure at 9506-mech.md:85-91, MATCH).
Slice 4 -- attested run:
  ./test/incus/with-cluster.sh '9506 mech reattest' -- \
      ./test/incus/t12-g2-9506.sh --d11-reattest
  Single run; no rerun-and-tune. The D11-specific ledger is the acceptance
  artifact; the ordinary 30-row T12/G2 ledger is not claimed to pass. Preserve
  the D11 archive + full observer snapshots + counter windows.
Slice 5 -- record and close:
  Append the run record to docs/log/9506-mech.md (or docs/log/10484.md), file
  the D11 ledger, and close #10484 only if section 8 holds. #9506 stays OPEN
  (counter slice pending) per campaign tracking.

### 7.1 Ledger convergence and acceptance boundary

The existing script has 30 rows and exits 2 when any row is VOID (:2320-2347).
Several of those rows are intentionally unrelated measurement-incomplete cells,
so merely appending four D11 rows would make a successful D11 run impossible.
The --d11-reattest branch MUST select the D11 row buffer before the existing
30-row emission loop, run the shared setup and restore proof, and use a
separate exact four-row count. It MUST NOT relabel, delete, or silently pass
the ordinary rows.

The accepted #10484 run is: `t12-g2-9506.sh --d11-reattest` with
`T12_D11_SUMMARY cells=4 pass=4 fail=0 void=0 exe_check=MATCH`, converged
fixtures, per-node composite-key attribution, and clean restore. The no-arg script
remains the broader r6 ledger, not this follow-up's acceptance command.

## 8. Proof cells and kill-gates

PASS requires ALL of: exe_check=MATCH (local==fw0==fw1, t12-g2-9506.sh:1687-1697);
complete_fixture=1 with stn/xfrm_sa/divert_table all 1 on both nodes
(:1900-1902); manifest of N<=32 captured marker frames total across both
nodes, each with node_id, bytes digest + origin + local queue/lease identity
(including local permit_epoch) + trigger-assigned request_id; the bounded Go
D11 ledger has exactly one ADMIT_OK record and exactly one completion record
(`resolve_count==1`, terminal state) for every composite key
`(node_id, request_id, local lease tuple)` and no extra keys
(admitted==completed==manifest sets); exactly one Rust worker verdict per key;
LateCompletions, Timeouts, Uncertain deltas == 0; Rust provenance row per key
matches request/lease/origin and the independently computed digest with
expected outcome; E28 split holds (Rust-52-delta==0;
Go-52-delta==WouldPermit-count; suppressed-delta==WouldPermit-count); never-q0
holds (per-key + global halves, section 6.4); routine-path pollution deltas
== 0 (quiesce guard); Q4 re-grounding records leg 1 preserved for
ordinary/non-trigger frames and the trigger-only selection exception; shared
restore clean (fw0/fw1_config_cmp=1, residue clear, probe errors=0) with D11
rows buffered until after restore. The mode emits exactly four D11 rows, all
PASS, zero VOID/FAIL, exit 0.

VOID (never PASS, never FAIL): exe_check != MATCH; fixture-setup-failed (any
fix9506_setup step incl. RG2 failover); no captured marker frames; authority
drift (STALE) or any ADMIT refusal; any required observer unavailable (Rust
status, Go D11 ledger, Go metrics incl. NEW suppressed/deny surfaces, nfqueue,
st-links, digest/reason fields); routine-path pollution in-window; Q4 showing
default dark intact-but-unverifiable. A VOID run is retained as diagnostic
evidence but cannot close the issue.

FAIL (claim broken, not environment): Go ledger or Rust completion joined to a
wrong `(node_id, request_id, local lease tuple)`; duplicate or late completion;
ledger `resolve_count` not one or terminal-state mismatch; provenance
identity/digest/reason mismatch; outcome mismatch vs manifest expectation; any
Rust-52 among D11 rows; Go-52 or suppressed delta != WouldPermit-count; any
Written outcome (either half); PASS emitted before restore; D11 row-count != 4;
any D11 row silently omitted. Any FAIL kills the run: no close.

PLAN-KILL boundaries (return to owner for re-scope per the merge-gate
sequencing: #10483 ruling, #10484 before S9.5/counter reliance): the guarded
trigger cannot preserve every deny-only predicate (section 5.3 table); the
Rust admit-time digest witness or its additive status surface cannot be
produced, or the harness cannot independently compare it; the bounded Go
ledger cannot expose one authoritative record per
`(node_id, request_id, local lease tuple)` through the authenticated
`GetD11AttestationLedger` RPC; the run would need the S9.5 cutover (Option C) or
any product semantic change to default paths (e.g. removing pipeline.go:984,
splitting suppression counters, weakening submitEligible); the q0 negation has
no authoritative witness; per-composite-key D11-row Rust-52 isolation proves
impossible (global pollution with no row-reason path); cluster repair meets the
unsupported criteria (Q5); Q4 shows the DEFAULT dark path broken. None is
established on current source; all are falsifiable in Slice-1.
