# DRAFT v3: #10484 live re-attestation proving the D11 join before S9.5 relies on the bridge

Status: DRAFT v3 after residual adjudication. Folds round-1 hostile reviews (both
PLAN-NEEDS-MAJOR, convergent, no KILL): reviewer A (E28-impossible cell,
trigger-underspec, provenance-gap, predicates, citations) and reviewer B
(F1 permit contradiction, F2 E28, F3 provenance auth, F4 singleton/location,
F5 pending lifecycle, F6 mode gaps, F7 runbook, F8 boundary-holds). No
production code. No live run performed in-lane (cluster/incus commands are
forbidden in this lane; the attested run is prescribed for a lab-capable
lane). All source citations were re-grounded at base `4858dc2d4` for this
DRAFT v3 via `read`; grep snapshots drifted by 2 lines in `pipeline.go` during
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
- Base contains the bridge: b71c52d6093f IS an ancestor of HEAD 4858dc2d4
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
base commit 4858dc2d4. The merge-gate sequencing was 10485 -> 10484 -> counter
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

V3 implementation blast radius (NEW work this plan designs; no S9.5 cutover,
no product semantic change to default paths):

| Ownership point | Files (existing anchors; NEW code marked) | Tests |
| --- | --- | --- |
| Go trigger seam | NEW pkg/nfqueue/pipeline_attest_10484.go: guarded `AttestSubmit` helper, called only by a NEW `dispatchAttestEligible` seam inserted at pipeline.go:462-464 immediately before `submitEligible`; marker selection reads captured `frame.Packet.Payload()` from `eligibleLocked` heads (:529-545), never scans `p.flows` later and accepts only a bounded nonempty decoded `marker_hex` selector from control—not caller frame bytes, request IDs, or attribution rows; daemon arm callback is in the ipsec_capture_wiring_9506.go authority region (Slice-1 freezes the exact callback line) | default-off (no arm flag -> errAttestDisabled, zero behavior delta, existing suites green); marker heads withheld from routine suppression while armed; one-shot arm (second arm rejected; run/generation-bound); captured-frame-only (raw bytes / non-NFQUEUE frame rejected); pending cleanup on timeout (Poll :848-869), revoke (Cancel :1014-1138), restart (authority reset); trigger-removal census (only consumeFrames seam + arm wiring references) |
| Rust provenance + authority | slowpath_reinject_9506.rs: internal admit-time digest witness (bytes available at :847-920), terminalize row+reason (:1359-1425), terminal tombstones (NEW set in CoreInner :608-621), run_id reset extension (:352-362) | harness independently recomputes and compares the digest; tombstone reuse refused; provenance cap/eviction (PROVENANCE_MAX=128 :498) per-daemon D11 cap guard; additive status exposure compat (existing chain slowpath.rs:1483-1484 -> coordinator/status.rs:934-940 -> helpers/status.rs:547) |
| Metrics/witness export | pkg/api/server.go:101-120 witness +2 fields (NEW); pkg/api/metrics_ipsec_capture_10478.go:14-59 collector +2; pkg/api/metrics_descriptors_controlplane.go descs +2; pkg/daemon/daemon_run_servers.go:709 callback feeds them; daemon DenyEventSink wiring (NEW counting sink; today zero production setters) | descriptor coverage test extends metrics_ipsec_capture_10478_test.go pattern; unavailable-omitted preserved (:19-21) |
| Management/status RPC | proto/xpf/v1/xpf.proto + generated BpfrxService: NEW GetD11AttestationLedger and bounded D11LedgerRecord schema; authz adds a PermMaint method entry plus a reviewed `methodsWithoutCanonicalCommand` reason because this is a privileged diagnostic, and the handler requires UID 0/superuser server-derived peer-UID principal (not a generic maintenance class); daemon-owned final snapshot remains after runtime reset | generated RPC client polls fw0/fw1 with stable snapshot_seq, exact run_id, finalized/no-truncation gates; non-privileged-principal denial, UID-0/configured-superuser allow cases, method-table completeness, and cap/truncation selftests |
| Script mode + driver | t12-g2-9506.sh: --d11-reattest case (:19-33), D11 branch populates `D11_ROWS_FILE`, assigns `CELL_ROWS_FILE=$D11_ROWS_FILE`, buffers with existing `CELL_BUFFER_ONLY=1`, then sets `CELL_BUFFER_ONLY=0` immediately before replay (:2322-2336), T12_D11_SUMMARY (distinct from T12_G2_SUMMARY :2342), minimal v4_native x2 fixture via fix9506_setup/teardown, shared restore proof | --selftest hermetic trigger/attribution/shape/refusal cases + no-arg regression pin (still 30 rows, exit 2 on VOID) |

Gate: DESIGN (recorded 2026-09-22, re-affirmed in v3). Mechanical is refused
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
file:line; the contract is frozen, while the file:line pins remain outstanding.

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
  pre-run, recorded in the run record and ledger header). Rust stores run_id
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
  reconciliation, and rollback each acquire `authorityMu` exactly once before
  installing/reading/clearing the override and invoking
  `announceAuthorityLocked`; no caller takes it twice. Reconnect does not
  acquire `authorityMu`: arm/reconcile/rollback update the submitter's cached
  `announcePayload` while holding `authorityMu`, and `ensureSubmitLocked`
  replays that already-cached override tuple under `submitMu`
  (reinject_socket.go:93-111). While active, the locked helper returns/replays
  the override's `run_id=attest-<nonce>`, generation, permit epoch, OPEN bit,
  and queue rows instead of allowing actor.Status().RunID or a normal refresh
  to overwrite it.
- After P1 is already OPEN, the arm callback first reserves ARMING, then holds
  `authorityMu`, installs the override, calls the existing connected client's
  `AnnounceReinject` through `announceAuthorityLocked`, and records the
  announced tuple. It publishes ARMED before unlocking; dispatch refuses all
  trigger heads until that state is visible. The same run nonce/selector
  binding is installed independently on fw0 and fw1 (with node-local permit
  epochs). Any announce failure clears the override, re-announces normal
  authority under the same lock, records the nonce VOID, and never exposes
  ARMED; reconnect uses the existing replay path, never a second socket.
- Run binding: the attestation run uses run_id `attest-<nonce>` (NEW convention;
  nonce is exactly 128 bits rendered as lowercase hex, generated by the harness
  pre-run, recorded in the run record and ledger header). The `attest-`
  namespace is the attestation gate; Rust stores run_id (:377), and the frame
  digest (section 6) mixes the stored run_id, binding every admitted frame to
  this exact authority namespace. A concurrent or replayed announce with a different
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
  (1) transition ARMED->DRAINING: reject new arm/disarm requests and stop new
  selections while retaining run state; (2) scoped `CancelReinject` for the
  lab permit epoch/queue scopes (`Cancel` :1014-1138; submitGate write lock
  :1018 linearizes against in-flight submits); (3) drain completions via Poll
  (:828-847) until pending empty and verify `p.pending`/every `flow.pending`
  is empty; transition DRAINING->DISARMED only after this drain; (4) under
  the with-cluster rollback exclusion, the close coordinator acquires the
  existing `applySem` owner (`reconcileIpsecHostInputFence` takes it at :137-140),
  suppresses the normal reconciler/reopen path, and revalidates that ownership across every readback.
  Capture `expectedOpen := supervisor.loadPermit()` and require it is OPEN,
  then call `retireHostInputFenceOverlay(cfg, expectedOpen)` (:242-283) before
  revoking. Its old-set conntrack ACK plus empty-candidate nft/readback is the
  only accepted fence retirement, and the concurrent-authority check must pass
  (the test contract :261-263). Never use `reconcileIpsecHostInputFence` for
  this close step: its CLOSING branch can call
  `tryOpenIpsecPermitAfterFenceAck` (:153-156, :208/:213/:242). A retirement
  error is VOID and blocks every later step. Keep `applySem` held and
  revalidate its owner through (5) Rust `close_permit` (:408-416) and tombstone
  lab queue epochs (:390-396), (6) topology revoke with
  `revokeTransitPermitNonblocking` (:260-299), and (7) hand teardown to
  `ipsecCaptureRuntime.close` (:626-667), which stops listeners/actors, closes
  queues and submitter, retires handles, and returns a positive close ACK.
  With the existing submitter still connected, those close/tombstone writes
  ensure no further admission can cross the close. (8) only after the
  applySem owner has revalidated all fence/readback, listener, queue-destruction,
  and close ACK gates does the S4 close coordinator (NEW call at the existing
  owner boundary) take `drainCommitLeases` (:304-314) and invoke
  `finalizePermitClose` (:316-340). Direct trigger-side finalization is
  forbidden. Slice-1 pins a unit transition test OPEN fence-retire ACK ->
  revoke/CLOSING -> no reopen arm -> finalizable.
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
  `userspace-attest:arm:<run_id>:<permit_epoch>:<marker_hex>`.
  The request carries only the run/nonce scope, that daemon's locally
  observed supervisor `permit_epoch`, and `marker_hex` solely as the bounded
  selector: exactly 32 lowercase hex characters decoding to 16 bytes. A
  frame is selected only when its captured bytes parse as IPv4 with a valid
  IHL and ICMP echo, the ICMP data has at least 32 bytes, and those 16 bytes
  equal data offsets 16..31 (beyond the ping timeval); the driver emits this
  selector with `ping -p`, while the digest covers the full `Packet.Payload()`.
  The request carries no frame bytes, manifest count,
  request ID, or caller-authored attribution manifest. `D11ManifestCap=32` is
  a daemon constant, not caller input. `dispatchAttestEligible` applies the
  exact predicate to the next real NFQUEUE `CaptureFrame` inside
  `consumeFrames`; all marker/owner, origin/STN, lease, and digest attribution
  rows are created internally from the selected frame.
  The run_id/nonce is common to both daemons, and each daemon wires the action
  to a NEW `D11AttestationArmer` callback in its
  ipsec_capture_wiring_9506.go authority region.
  Existing SystemAction authorization must require a server-derived
  peer UID of 0 or a configured superuser for this prefix-form action;
  `PermMaint` alone is insufficient because the current command gate rejects
  restricted classes with no canonical resolver
  (authz_command_gate_7172.go:77-82, :113-117). Before mutation, reject a
  missing arm environment, a principal that is neither UID 0 nor a configured
  superuser, malformed run/nonce, absent local D11 wiring or authority
  snapshot, or an already-active run.
  There is no node-wide "primary" rejection: RG ownership is checked per
  marker below, because RG1/fw0 and RG2/fw1 both participate. The action is an
  arm request only; it does not dial either reinject socket.
- One-shot and nonce binding: `ArmD11` stores
  `(node_id, run_id, nonce, local_permit_epoch, marker_selector)` and
  atomically reserves `INACTIVE -> ARMING`; `marker_selector` is validated
  from `marker_hex` but is only a selector, never attribution data.
  `dispatchAttestEligible` accepts no trigger head while the state is ARMING.
  The armer then holds `authorityMu`, installs the attestation override, and
  successfully calls the existing `AnnounceReinject` path. While still holding
  that lock, it publishes `ARMED`; dispatch accepts
  trigger heads only in ARMED. If announce fails, it clears the override,
  re-announces normal authority under the same lock, records the nonce VOID,
  and returns to INACTIVE without ever exposing ARMED.
  A second arm for the same node/run/epoch pair, or any different pair while
  one is active, is rejected. The ARMED run may consume at most
  `D11ManifestCap` distinct internally selected NFQUEUE heads on that daemon;
  request IDs are unique and terminalized once. Disarm is irreversible for
  that run and is allowed only after the rollback drain; a same-nonce re-arm
  is refused until daemon restart. The exact `attest-` authority namespace,
  captured marker prefix, origin/STN ownership, lease tuple, and digest run
  mix-in are derived from the selected frame and common nonce; mismatch is
  VOID and never submits.
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
  `(attest, ordinary)` using `eligibleLocked` heads (:529-545), the decoded
  nonempty `marker_hex` selector (exactly 16 bytes), and the full captured
  `Packet.Payload()` (nfqueue.go:373-427). A frame matches only if it is IPv4
  with valid IHL and ICMP echo, has at least 32 ICMP-data bytes, and the
  selector equals data offsets 16..31; the digest still covers the full frame.
  It MUST NOT scan `p.flows` from a later control call, accept a raw-byte
  argument, or select an already-consumed frame. An armed, exact-marker head
  is removed from `ordinary` and sent to
  `AttestSubmit` before ordinary `submitEligible`; an unrelated non-marker,
  unarmed frame, or marker that is not this node's exact internally configured
  marker stays in `ordinary` and reaches the existing suppression arm
  unchanged. An exact-marker head with wrong origin/STN/RG ownership is instead
  a selected D11 row and becomes the named VOID from the preceding bullet; it
  is never silently routed through suppression.
- Validation, mint, reservation, submit ordering: `dispatchAttestEligible`
  enters with `drainMu` held for the whole batch and takes
  `submitGate.RLock` before touching the selected heads. It first runs the
  shared L2, zone, generation, authority, and exact-origin/STN predicates
  without `p.mu`; a failure terminal-drops that selected head, records the
  named D11 VOID reason, and never enters ordinary suppression. For a passing
  head it calls `MintLeaseForAttest` before reservation, producing the unique
  request ID plus local lease tuple under the exact `attest-<nonce>` authority
  and permit epoch. A mint failure has the same pre-reservation VOID unwind:
  no `p.pending`, `flow.pending`, ledger admission row, or socket I/O.
  With the request ID and lease now present, it takes `p.mu`, rechecks that
  the selected flow is still eligible and unreserved, and atomically reserves
  the flow (`flow.pending`), `p.pending[request_id]`, and the daemon ledger
  record keyed by `(node_id, request_id, local lease tuple)` with internal
  `ADMISSION_PENDING`; `pending.deadline` remains unset while admission is
  pending. `AckDeadline` is the existing `p.ackDeadline` and defaults to 5 ms
  at pipeline.go:297-298; no trigger override is allowed. Unlock `p.mu` before
  constructing the batch or doing socket I/O, then call `SubmitAdjudicated`
  once while retaining `submitGate.RLock`; its admission response updates the
  ledger code under `p.mu`. Poll does not take `drainMu` while draining the
  separate completion socket (:823-845), so a completion can arrive while
  the row is still `ADMISSION_PENDING`: buffer it as `earlyCompletion` on that
  row under `p.mu`; first arrival wins, while a second pre-ADMIT_OK arrival
  marks duplicate/FAIL in a bounded row flag/counter and never overwrites the
  first. When the response arrives, atomically install ADMIT_OK,
  set `pending.deadline = time.Now().Add(AckDeadline)`, and apply the buffered
  completion; a refusal or transport error with a buffered completion
  terminalizes the ledger row Uncertain/FAIL, retaining admission code,
  early-completion/late-attempt evidence; clear only `p.pending` and
  `flow.pending`, never delete the ledger row or overwrite terminal state.
- Reservation/submit unwind table (every branch is fail-closed). Every branch
  releases `submitGate.RUnlock` while retaining `drainMu` before any scoped
  submitter cancellation; cancellation uses the lock-aware helper and MUST NOT
  re-enter `Cancel`/`drainMu`; pre-reservation branches perform no socket
  cancellation.
  - final eligibility or reservation recheck fails after mint but before the
    reservation is installed: discard the local lease/request allocation,
    terminal-drop and record D11 VOID, with no pending map/flow entry and no
    ordinary `V1PermitSuppressed` increment;
  - a defensive post-reservation authority/lease revalidation or lease
    finalization check fails before bytes are handed to the socket: under
    `p.mu` remove `p.pending[request_id]`, clear `flow.pending`, mark the
    ledger row D11 VOID, and terminal-drop; no remote cancellation is needed
    because no request was sent;
  - batch construction or submit encoding fails after reservation: remove the
    pending/flow reservation under `p.mu`, record the named transport VOID,
    and use the scoped submitter cancellation only if a remote request was
    actually sent;
  - a submitter transport/decode error after send: cancel all reserved request
    IDs by queue scope, clear each pending/flow entry, and mark each ledger row
    Uncertain; no retry may produce PASS;
  - `SubmitAdjudicated` returns without an admission response or its socket
    timeout fires: treat this as the submit transport/decode unwind above,
    cancel the scoped batch, clear pending/flow entries, and mark rows
    Uncertain; Poll cannot classify a missing admission response;
  - An admission response refusal records its exact admission code in the
    retained ledger row, clears only `p.pending`/`flow.pending`, and never
    deletes the selected-key record. `STALE`, `FULL`, and `SHUTDOWN` are
    environmental refusals -> VOID. `BAD_LEASE`, `BRIDGE`, `INPUT_HOOK`,
    `NON_DRY_RUN`, `NO_GENERATION`, and `TUNNEL_ROW_MISSING` are contract
    refusals -> FAIL when the frozen authority/lease/origin/generation
    preconditions were observed; if those preconditions are unavailable, VOID.
  - Poll skips timeout evaluation for rows with admission state
    `ADMISSION_PENDING` or a zero `deadline`; after ADMIT_OK, Poll (:823-867)
    finds no terminal completion by the stored `pending.deadline`: expire and
    clear pending, issue the existing scoped cancellation, and mark the row
    Uncertain/VOID per the cell contract; completion after expiry is
    `LateCompletions` and cannot reselect the head.
- `AttestSubmit` is an internal helper with no arbitrary-frame caller; it is
  reachable only from `dispatchAttestEligible` and receives already validated,
  already minted frames from this consume pass. It factors the shared
  predicates out of `submitEligible` so both paths use the same checks. No
  `p.mu` is held while acquiring the submitter `submitMu`; `Drain` holds
  `drainMu` across this sequence and `flow.pending != nil` excludes a head
  from `eligibleLocked`, so routine suppression cannot delete a selected frame
  or race it into a second batch.
- Lock order is explicit: `Drain` holds `drainMu`, then
  `submitGate.RLock`; reservation briefly takes `p.mu` and releases it before
  any submitter `submitMu` acquisition. No path holds `p.mu` while acquiring
  `submitMu`, and no path takes `p.mu` then `submitGate`; `Cancel` is
  `drainMu -> submitGate.Lock -> p.mu` (:1016-1019), `resolveCompletion`
  takes `p.mu` only (:925-970), and Poll does not hold pipeline locks around
  completion drain (:828-847). This order cannot recreate the selector race or
  deadlock cancellation/completion.
- Admission and pending lifecycle: call `SubmitAdjudicated` once for the
  selected batch and match every `ReinjectAdmission` by
  `(node_id, request_id, local lease tuple)`. ADMIT_OK waits for completion;
  refusal codes follow the environmental-versus-contract mapping in the unwind
  table, transport errors remain Uncertain, and AckDeadline expiry follows the
  same retained-row cleanup. A completion resolves through the existing
  Poll/resolve path and late completions cannot reselect a head.
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
  (1) transition ARMED->DRAINING: reject new arm/disarm requests and stop new
  selections while retaining run state; (2) scoped `CancelReinject` for the
  lab permit epoch/queue scopes (`Cancel` :1014-1138; submitGate write lock
  :1018 linearizes against in-flight submits); (3) drain completions via Poll
  (:828-847) until pending empty and verify `p.pending`/every `flow.pending`
  is empty; transition DRAINING->DISARMED only after this drain; (4) while OPEN,
  `retireHostInputFenceOverlay(cfg, expectedOpen)` supplies the conntrack/nft
  fence-retire ACK; (5) Rust close/tombstone while submitter connected;
  (6) topology revoke leaves Go CLOSING; (7) `ipsecCaptureRuntime.close`
  stops actors, closes queues/listener resources, and retires handles; (8) the
  S4 close owner drains commit leases and finalizes CLOSED; (9) observe Go
  CLOSED, then clear the override under `authorityMu` exactly once,
  restore/recreate the runtime, and announce normal CLOSED; (10) verify Rust
  CLOSED, Go CLOSED, arm disarmed, and shared restore/residue before ledger
  emission. Any failed step is VOID; a PASS row before the final proof is
  FAIL.

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
live ids only). V1's `authenticated` wording therefore overclaimed. V3 design
(NEW, Slice-1 freezes, Slice-2b builds):

- Rust witness, not an admission input: add `frame_digest: [u8;32]` and
  `reason: u8` to `ReinjectProvenanceRow`. The entry retains the computed
  digest internally until terminalization; no expected digest is added to
  `SubmitFrame` or the existing submit wire. At `admit_with_class`
  (:847-920), where the submitted bytes are present, hash the exact canonical
  preimage `ASCII("XPF-D11-FRAME/v1") || u32be(field_count=11) || fields`,
  with each field encoded as `u32be(byte_len) || bytes` in this order:
  `Packet.Payload()`, request_id/permit_epoch/queue_epoch as u64be,
  queue_number as u16be, wire-normalized family and hook as u8,
  `OwnedIfindex` as u32be, `Owner` and `STN` as UTF-8 strings, and UTF-8
  `authority.run_id`. Slice-1 pins the unit vector
  `(payload=001122, ids=request/permit/epoch/queue=1/2/3/4,
  origin-wire family=1/inet, hook=1/forward, owned_ifindex=5, owner=rg1,
  STN=stn1, run_id=attest-00000000000000000000000000000000)` to SHA-256
  `7972bbf33fb7f81d51ee31ab9b0588f3d104b33deb48e62de6bb9a7e24b05ab1`
  using `sha2` in `userspace-dp/Cargo.toml`. This is an admit-time witness,
  not a self-comparison and not an ADMIT_BAD_LEASE gate. `terminalize`
  (:1359-1425) copies the retained digest and reason into the row; status
  exposure reuses the existing chain with additive JSON fields (Slice-2b
  records wire-compat impact + test).
- Independent harness comparison: the driver does not submit a manifest or
  attribution data and does not reconstruct L3 bytes from `ping -p` arguments.
  The independent byte source is a NEW bounded snaplen-full in-tree NFLOG
  consumer attached to the same nftables FORWARD chain immediately before the
  NFQUEUE rule. Slice-1 pins the chain priority/rule order and proves this
  post-forward NFLOG payload byte-identical to NFQUEUE `Packet.Payload()`;
  pre-routing/ingress captures are forbidden because TTL/header checksum can
  differ. It records at most `D11ManifestCap=32` full packets per daemon per
  armed run window, with each snaplen capped at 65,535 bytes
  (`reinjectMaxData`), so the raw payload bound is 2,097,120 bytes per daemon.
  A 33rd matching capture sets `overflow/truncated` and forces VOID; inability
  to prove that fail-loud enforcement is PLAN-KILL before the run. Each marker
  request uses a harness-assigned non-reused ICMP identifier per direction; the
  observer key is `(node_id, src, dst, icmp_identifier, icmp_sequence,
  marker_selector)`.
  Slice-1 MUST implement the observer and a byte-equality proof before the D11
  run; if no such point can be proven, this plan is PLAN-KILLED rather than
  permitting bytes copied back from the Go ledger. The driver joins those
  observer bytes to the daemon/Rust record by `(node_id, request_id, local
  lease tuple)` and captured origin. The pipeline hashes `Packet.Payload()` at
  the existing submit-encode/admit boundary; the driver recomputes the same
  canonical bytes || lease || origin || announced common `attest-<nonce>`
  digest outside the admission path. Missing row, missing digest, or mismatch
  is FAIL; unavailable status is VOID. A bad harness computation cannot cause
  Rust to refuse a valid frame, while a Rust bug or harness misjoin remains
  observable as a failed comparison.
- NEW bounded Go join ledger with a concrete readable surface: keep a
  daemon-owned, run-scoped `D11AttestationLedger` (not a field of the capture
  runtime, not `IpsecCaptureWitness`, and not Prometheus), capped at the
  daemon constant `D11ManifestCap=32`, never caller-supplied. Runtime stop,
  authority override clear, Rust run-id reset, and capture restore/recreate
  MUST NOT clear it. The ledger remains queryable after rollback with its final
  snapshot; only a later explicit `ArmD11` for a new nonce may replace/clear
  the prior finalized ledger, after the driver has archived that final RPC
  artifact. Add the NEW unary gRPC method
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
  poll and once after rollback, running as root/superuser. It requires a
  stable `snapshot_seq`, exact `run_id`, `finalized=true` for the final
  artifact, and no truncation before comparing the internally selected,
  admitted, and completed composite-key sets independently on each node:
  `(node_id, request_id, local lease tuple)`. It never reconstructs a join
  from aggregate Prometheus counters.
- Each composite key `(node_id, request_id, local lease tuple)` record
  contains the captured origin, the independently recorded frame_digest,
  admission code, completion outcome, `resolve_count`, and terminal state.
  Create that record atomically with the `p.pending` reservation before socket
  I/O; the `SubmitAdjudicated` response updates its admission code under
  `p.mu`, and an early completion is buffered then applied atomically when
  ADMIT_OK installs its completion deadline. Update the record on every
  completion attempt, including duplicate/late attempts, and publish the final
  `resolveCompletion` outcome rather than leaving the bool internal.
  If the cap is exceeded, a selected frame is missing, or a second terminal
  transition is observed, the run is VOID/FAIL per section 6.4. Ledger
  publication is synchronized with pipeline terminalization; rollback marks
  the ledger finalized but never clears it, so the post-rollback RPC remains
  the acceptance artifact until the next explicit arm replaces it.
- Run binding + replay window: run_id `attest-<nonce>` stored at publish
  (:377); the Rust digest mixes it, so the harness comparison rejects a
  cross-run misjoin. NEW terminal tombstones: BTreeSet<u64> in CoreInner
  (:608-621), inserted at terminalize, consulted at admit (member ->
  ADMIT_BAD_LEASE), cleared ONLY on the run_id-change reset path (:352-362,
  extended). Go request_ids are already monotonic per actor
  (requestID.Add(1) :512-515). Internally selected-set equality and the Go
  ledger close the loop harness-side.
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
  Slice-1 records this verbatim; any v3 sentence still saying bare `authenticated` is a defect.
- PLAN-KILL (narrowed): if the digest witness cannot be generated at the Rust
  admit point and independently exposed for harness comparison, or the
  run-scoped Go ledger cannot expose one authoritative record per
  `(node_id, request_id, local lease tuple)` (admission, completion outcome,
  resolve count, terminal state) through the authenticated
  `GetD11AttestationLedger` RPC, sequencing returns to the owner. Missing
  witness stays fail-closed: VOID, never inferred.

- Q1 (join observability): ARM SHAPE FROZEN; file:line pins remain outstanding
  per Slice-1a. Pending gate (:925-936) + lease/bytes checks (:937-943) +
  terminal arms (:953-990) are verified. The
  sole arm grammar is
  `userspace-attest:arm:<run_id>:<permit_epoch>:<marker_hex>`. Its frozen
  tuple is `(run_id/nonce common, node-local permit_epoch, marker_selector)`;
  `marker_hex` is exactly 32 lowercase hex characters decoding to a 16-byte
  selector, and selection requires IPv4/valid-IHL/ICMP-echo with at least
  32 ICMP-data bytes whose offsets 16..31 equal that selector. The request
  carries no frame bytes, manifest count, request ID, or attribution manifest.
  `D11AttestationArmer`, `dispatchAttestEligible` insertion before
  `submitEligible`, node-local composite ledger, close-owner transition,
  byte-identical independent capture observer, and authenticated Go-ledger RPC
  are the exact implementation contract; no alternative arming shape is
  permitted.
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
- Q3 (workload shape and binding): `v4_native x2` means two logical marker
  flows: one even/RG1/fw0 and one odd/RG2/fw1 (fixture_probe_indices
  t12-g2-9506.sh:96-102; fixture_measure_traffic :1440-1498; XFRM if_id
  0x25220001/2). Each flow emits exactly two uniquely identified ICMP echo
  requests, one per decrypted direction. Each of the four internally selected
  marker `CaptureFrame`s creates a daemon ledger row with
  node_id, captured bytes digest, origin, and that node's local queue/lease
  identity and observed permit_epoch; request_id is assigned by the trigger
  after capture and lease mint. The D11 observer joins on the composite key
  `(node_id, request_id, local lease tuple)`, matching origin + digest in the
  Rust provenance row and Go per-node ledger before counting; no arm request
  or caller-authored manifest supplies any of those fields. The ledger must
  show one admission, one completion, resolve_count==1, and terminal state.
  XFRM deltas corroborate fixture readiness ONLY. `D11ManifestCap=32` is
  enforced independently per daemon (64 combined upper bound), while the
  harness acceptance selects exactly four total selected rows across both nodes:
  two packets per marker flow (four selected-frame ledger records, distinct
  from the four proof-cell rows; not four flows). PROVENANCE_MAX=128
  evict-oldest at :1404-1408 leaves 4x headroom per process; quiesce means no
  concurrent admitters.
  Missing witness/ledger row -> VOID, never infer.
- Q4 (dark-triple re-grounding): REQUIRED with a §8 gate (new in v3). Leg 1
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
  criteria (new in v3). Order verified against manager_ha TakeoverReady
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
on `(node_id, request_id, local lease tuple)`. For each node,
`selected == admitted == completed` over composite-key sets with no
extra/missing/duplicate key. Absolute counters are never asserted.
Any required surface unavailable -> VOID with the surface named. Routine-path
trigger window is quiesced (fixture pings paused except marker packets); any
nonzero delta in routine-only counters (ZoneGateDrops and friends) -> VOID
  (pollution), never subtracted out.
| Cell | Proves | Observer (authoritative surface) | VOID if | FAIL if |
| --- | --- | --- | --- | --- |
| d11_9506_submit_admit | trigger + admit + 26B tail/generation acceptance, both nodes | Go D11 ledger admission records keyed by (node_id, request_id, local lease, origin, digest, admission code) plus ADMIT responses per composite key (ADMIT_OK :41) + adjudicated_admitted delta (:1427-1431) | authority drift (STALE), FULL, SHUTDOWN, or required precondition/ledger status unavailable -> VOID | duplicate composite key admitted twice (:886-887 bypassed); BAD_LEASE/BRIDGE/INPUT_HOOK/NON_DRY_RUN/NO_GENERATION/TUNNEL_ROW_MISSING after frozen authority/lease/origin/generation preconditions -> FAIL; admitted key outside the internally selected CaptureFrame rows; ledger record differs from ADMIT |
| d11_9506_worker_verdict | Rust adjudication + transport + terminalization; split Deny/WouldPermit; never q0 | provenance rows keyed by (node_id, request_id, local lease) with outcome split, origin, independent digest + row reasons (NEW fields); q0 primary witness below | status surface unavailable, non-final snapshot, or no readable rows before any selected key is admitted | finalized selected/admitted key missing a provenance row or digest (including eviction), outcome/identity/digest mismatch vs internally selected CaptureFrame expectation; ANY row reason==52; ANY row outcome==written (Rust half of never-q0) |
| d11_9506_completion_join | end-to-end join, the only true join proof | Go D11 ledger (one admission, one completion outcome, resolve_count==1, terminal state per (node_id, request_id, local lease)) + Rust rows with same key (origin/digest match) + LateCompletions delta==0 (:929) + Timeouts delta==0 (:848-869) | any observer unavailable; completions pending past deadline without terminal state | misjoin (wrong node/id/lease/origin/digest); duplicate terminal; late completion; resolve_count!=1; missing row; Go/Rust outcome disagreement |
| d11_9506_wouldpermit_accounting | suppression accounting split (section 6.1) | Rust row reasons (52-delta==0) + NEW xpf_ipsec_capture_suppressed_total (delta==WouldPermit-count) + NEW xpf_ipsec_capture_deny_events_total{reason=52} (delta==WouldPermit-count) | metrics/sink unwired; reason field absent | Rust-52-delta!=0; Go-52-delta!=count; suppressed-delta!=count; WouldPermit row carrying reason 52 |

- Never-q0 witness (complete): PRIMARY per-key: every internally selected
  composite key `(node_id, request_id, local lease tuple)` has a Rust
  provenance outcome != "written" (:228-242 outcome strings; terminalize
  mapping :1412-1423) AND a Go ledger completion outcome != Written with
  `resolve_count==1` and terminal state. SECONDARY global:
  completed_written (:1413), Written (:218), Reinjected (:232) deltas == 0
  over the window. Either half violated -> FAIL. Either half unobservable ->
  VOID.
- Negative controls (hermetic, in `--selftest`, mirroring cell_verdict
  conservatism at t12-g2-9506.sh:986-1003): mutate the independent observer's
  captured bytes before digest calculation and require a digest mismatch FAIL
  in the harness (there is no Rust refusal based on an expected digest);
  wrong-lease completion -> Uncertain + DROP (:937-947, :971-981); duplicate
  completion -> LateCompletions + resolve false (:928-932); unknown id ->
  LateCompletions; already-terminal second verdict refused (terminalize guard
  :1366-1402). Live run carries no adversarial injection beyond the selector
  and real marker traffic.
- E28 delta semantics: Rust-52 from NEW row-reason bytes (per composite
  key, no pollution); Go-52 from NEW deny-event metric (per-run window;
  routine 52s from :653-660 etc. are excluded by the quiesce guard, and any
  routine traffic in-window voids the run rather than being subtracted).
- Mode mechanics (exact): add `--d11-reattest` case to arg parse (:19-33);
  D11 branch populates `D11_ROWS_FILE`, assigns `CELL_ROWS_FILE=$D11_ROWS_FILE`,
  and uses existing `CELL_BUFFER_ONLY=1` while collecting; immediately before
  replay sets `CELL_BUFFER_ONLY=0` and replays the 4-row buffer (:2322-2336;
  restore demotion
  :2329-2334 applies to D11 rows identically -- a PASS
  written before restore is FAIL per section 8); separate gate
  `D11_CELL_COUNT==4`, pass==4, fail==0, void==0, exit 0; summary
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
     `userspace-attest:arm:<run_id>:<permit_epoch>:<marker_hex>`
     sent independently to fw0 and fw1; `marker_hex` is a bounded nonempty
     selector only, never frame bytes, request ID, count, or attribution
     manifest. Server-derived peer UID 0 or configured superuser is required
     for both arm and ledger reads (prefix-form SystemAction cannot use generic
     `PermMaint`); D11AttestationArmer callback; one-shot binding
     `(run_id/nonce common, node-local permit_epoch, marker_selector)`; the
     pipeline selects the next real NFQUEUE frame and creates all attribution
     rows internally, with per-frame RG/origin/STN ownership.
     Pin the authorityMu/authoritySnapshotLocked/announceAuthorityLocked
     lock ownership (no recursive acquisition), the NEW `consumeFrames`
     :462-464 interception before `submitEligible`, captured-byte marker
     selection, zone/lease/admit call sequence with every error arm, the
     deny-only table, and the census test placement. Freeze rollback ordering:
     OPEN `retireHostInputFenceOverlay` ACK before revoke, runtime close,
     queue/listener teardown ACK, S4 close-owner finalization, then normal
     CLOSED re-publication; `reconcileIpsecHostInputFence` is not the close
     primitive. Freeze Q2 tail bytes + flags + generation window, the admit-time
     digest witness, and the independent full-copy NFLOG observer attached to
     the same nftables FORWARD chain immediately before NFQUEUE; pin the chain
     priority/rule order and key `(node_id, src, dst, icmp_identifier,
     icmp_sequence, marker_selector)`. If byte-equality or overflow fail-loud
     proof is unavailable, PLAN-KILL before the run. Freeze the concrete
     authenticated bounded `GetD11AttestationLedger` RPC schema/retention.
     Freeze metric names and all status/ledger gates. The contract is frozen;
     Slice-1 completes the outstanding file:line pins before implementation.
     Refusal precedence is frozen: if an admission refusal and an early or
     late completion co-occur, retain and terminalize that ledger record as
     Uncertain/FAIL (contract refusal -> FAIL), never collapse it to blanket
     VOID; clear only pipeline pending pointers.
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
  c. Go observability diff: daemon-owned bounded run-scoped
     `D11AttestationLedger`, keyed by `(node_id, request_id, local lease
     tuple)` and carrying origin/digest, admission code, completion outcome,
     resolve_count, terminal state, and late attempts. Expose it through NEW
     `GetD11AttestationLedger` in `proto/xpf/v1/xpf.proto` and the generated
     service/handler callback, with `PermMaint` plus a reviewed
     `methodsWithoutCanonicalCommand` entry and server-derived UID 0 or
     configured-superuser gate (not a generic maintenance-only path). This is
     not the scalar `IpsecCaptureWitness`/Prometheus callback; retain the
     finalized snapshot across runtime close/authority reset until a later
     explicit arm replaces it. Add only Suppressed + Deny52 to
     `IpsecCaptureWitness`/Prometheus (server.go:101-120); collector +2
     (metrics_ipsec_capture_10478.go:14-59, unavailable-omitted preserved);
     descriptors +2 (metrics_descriptors_controlplane.go); daemon callback
     feeds them (daemon_run_servers.go:709); daemon counting DenyEventSink
     wiring (NEW; today zero production setters). Extend descriptor, RPC-auth,
     and ledger coverage tests.
  d. Script mode + driver: --d11-reattest per section 6.4; trigger driver
     (internal ledger rows, marker traffic, counter sampling, set-equality join);
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
so merely appending four proof-cell rows to that 30-row output would make a
successful D11 run impossible.
The --d11-reattest branch MUST populate `D11_ROWS_FILE` with the D11 rows,
assign `CELL_ROWS_FILE=$D11_ROWS_FILE` and set existing `CELL_BUFFER_ONLY=1`
while collecting; set `CELL_BUFFER_ONLY=0` immediately before the existing
30-row emission loop, run the shared setup and restore proof, and use a
separate exact four-row count. It MUST NOT relabel, delete, or silently
pass the ordinary rows.
The accepted #10484 run is: `t12-g2-9506.sh --d11-reattest` with
`T12_D11_SUMMARY cells=4 pass=4 fail=0 void=0 exe_check=MATCH`, converged
fixtures, per-node composite-key attribution, and clean restore. The no-arg script
remains the broader r6 ledger, not this follow-up's acceptance command.

## 8. Proof cells and kill-gates

PASS requires ALL of: exe_check=MATCH (local==fw0==fw1, t12-g2-9506.sh:1687-1697);
complete_fixture=1 with stn/xfrm_sa/divert_table all 1 on both nodes
(:1900-1902); no more than `D11ManifestCap=32` internally selected rows
per daemon (the D11 run selects exactly four total across both nodes), each
with node_id, bytes digest + origin + local queue/lease identity
(including local permit_epoch) + trigger-assigned request_id; the bounded Go
D11 ledger has exactly one ADMIT_OK record and exactly one completion record
(`resolve_count==1`, terminal state) for every composite key
`(node_id, request_id, local lease tuple)` and no extra keys
(admitted==completed==internally-selected sets); exactly one Rust worker
verdict per key; LateCompletions, Timeouts, Uncertain deltas == 0; Rust
provenance row per key matches request/lease/origin and the independently
computed digest with the expected non-Written outcome; E28 split holds
(Rust-52-delta==0; Go-52-delta==WouldPermit-count;
suppressed-delta==WouldPermit-count); never-q0 holds (per-key + global
halves, section 6.4); routine-path pollution deltas == 0 (quiesce guard);
Q4 re-grounding records leg 1 preserved for ordinary/non-trigger frames and
the trigger-only selection exception; shared restore clean
(fw0/fw1_config_cmp=1, residue clear, probe errors=0) with D11 rows buffered
until after restore. The run retains exactly four selected-frame ledger records;
the mode emits exactly four proof-cell rows, all PASS, zero VOID/FAIL, exit 0.
VOID (never PASS, never FAIL): exe_check != MATCH; fixture-setup-failed (any
fix9506_setup step incl. RG2 failover); no captured marker frames; authority
drift (STALE), FULL, SHUTDOWN, or required selector/authority/generation
precondition unavailable; those environmental refusals are VOID; any required
observer unavailable (Rust status, Go D11 ledger, Go metrics incl. NEW
suppressed/deny surfaces, nfqueue, st-links, digest/reason fields, or the
independent byte-identical capture observer); routine-path pollution in-window;
Q4 showing default dark intact-but-unverifiable. A VOID run is retained as
diagnostic evidence but cannot close the issue.
FAIL (claim broken, not environment): Go ledger or Rust completion joined to a
wrong `(node_id, request_id, local lease tuple)`; duplicate or late
completion; ledger `resolve_count` not one or terminal-state mismatch;
provenance identity/digest/reason mismatch; outcome mismatch between the
internal selected row, Go ledger, and Rust provenance; BAD_LEASE/BRIDGE/
INPUT_HOOK/NON_DRY_RUN/NO_GENERATION/TUNNEL_ROW_MISSING after frozen
preconditions -> FAIL; any Rust-52 among D11 rows; Go-52 or suppressed delta
!= WouldPermit-count; any Written outcome (either half); PASS emitted before
restore; `D11_CELL_COUNT != 4`; any selected-frame ledger record silently omitted. Any FAIL kills the run: no close.

PLAN-KILL boundaries (return to owner for re-scope per the merge-gate
sequencing: #10483 ruling, #10484 before S9.5/counter reliance): the guarded
trigger cannot preserve every deny-only predicate (section 5.3 table); the
Rust admit-time digest witness or its additive status surface cannot be
produced; the bounded byte-identical capture observer, its byte-equality or
overflow fail-loud proof cannot be produced, or the harness cannot independently
compare it; the bounded Go ledger cannot expose one authoritative record per
`(node_id, request_id, local lease tuple)` through the authenticated
`GetD11AttestationLedger` RPC; the run would need the S9.5 cutover (Option C) or
any product semantic change to default paths (e.g. removing pipeline.go:984,
splitting suppression counters, weakening submitEligible); the q0 negation has
no authoritative witness; per-composite-key D11-row Rust-52 isolation proves
impossible (global pollution with no row-reason path); cluster repair meets the
unsupported criteria (Q5); Q4 shows the DEFAULT dark path broken. None is
established on current source; all are falsifiable in Slice-1.
