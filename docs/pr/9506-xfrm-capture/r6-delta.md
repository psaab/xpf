# #9506 r6 delta memo — r5 regrounded on current master

- r5 base: 7ef226474 (research/9506-xfrm-capture plan.md, 825 lines, read fully incl. S12-S12.6).
- Current: research/9506-reground @ c26bf5e7e (master at reground time; all citations reground-worktree absolute paths).
- Method: every load-bearing codebase claim → CONFIRMED / FALSIFIED / STALE-UNCERTAIN with current file:line. CONFIRMED-UNBUILT = r5 correctly describes absence/proposal state and no conflicting code exists.
- Counts: 58 checked / 41 CONFIRMED (22 built + 19 unbuilt) / 11 FALSIFIED / 6 STALE-UNCERTAIN. Every FALSIFIED row carries a current-master citation.
- Landed by parent from scout report (scout lane is read-only); no product code touched, no PR to master.

## Per-section claim table

### S1 Framing (threat model — the load-bearing section)

- C01 bind-interface stN route-based IPsec is the only IPsec model: CONFIRMED — pkg/config/compiler_ipsec_plaintext_warn.go:20-22 (ONLY model; policy-based hard-rejected #3114); compiler_prewalk.go:367-369.
- C02 Kernel XFRM decrypts; plaintext surfaces on xfrmi: CONFIRMED — pkg/dataplane/userspace/ingress_exclusions.go:183-184; userspace-dp/src/server/README.md:254-256.
- C03 xfrmi excluded from AF_XDP adjudication in BOTH planes (SecureTunnel class; include_userspace_binding_interface): CONFIRMED — Go ingress_exclusions.go:141 + :381-382; Rust planning.rs:433-450 + userspace_unbindable_netdev. Drift note: keying now ownership-or-device-kind (snapshotSecureTunnel union, interfaces.go:856), not lexical; r5 pins no keying so the two-plane claim stands.
- C04 Armed forward path deliberately open (gate removes barrier when armed): FALSIFIED (#10302) — pkg/daemon/daemon_transit_gate.go:52-56 (forward hook remains policy-DROP while armed); applyTransitBarrier(true) installs fence never removes (:385-411); transit_gate_tick_9725.go:63-89; pkg/nftables/transit_barrier.go:140-150; pins transit_fence_10302_test.go, transit_barrier_7191_test.go:46-58.
- C05a Admission warning-only: CONFIRMED — warnSecureTunnelPlaintextUnadjudicatedAST never rejects (compiler_ipsec_plaintext_warn.go:120-186; pkg/config/README.md:1371-1374).
- C05b Advisory prose still kernel-forwarded and still unadjudicated: FALSIFIED (prose stale) — same file :102-104. Forwarded false for FORWARD transit post-#10302 (fence DROPs xfrmi ingress; transit_barrier.go comment remains dropped). Unadjudicated still true (dropped without policy; INPUT/host-bound untouched by FORWARD fence).
- C06 Authenticated peer inner packets forward with no policy/session/NAT/screen/counter/deny: FALSIFIED (inverted) — steady-state xfrmi FORWARD transit now fence-dropped (daemon_transit_gate.go:123-124). Residuals: (a) marked xpf-usp1 q0 (adjudicated MissingNeighbor + synthetic IPsec only, #10391, slowpath.rs:974-984); (b) INPUT/host-bound decrypted ingress (FORWARD fence covers hook forward only). Threat moved fail-open-forward → fail-closed-drop + narrow residuals.

### S2 Scope / economics

- C07 2,797 ns whole-box reciprocal: STALE-UNCERTAIN — derivation lives in #8276 artifacts, not bench source.
- C08 111 ns rows include the copy: STALE-UNCERTAIN — rows exist but no recorded numbers in-tree; needs bench run.
- C09 Cross-thread consumer reads only f.len(): CONFIRMED — userspace-dp/benches/b2_capture_bridge.rs:151.
- C10 Cross-thread row sync_channel vs production mutex VecDeque: CONFIRMED — b2 header (slowpath sync_channel 16384; worker Arc<Mutex<VecDeque>> 4096) + bench_cross_thread_roundtrip.
- C11 No batched bench row: CONFIRMED — criterion_group! 4 benches (:173-179), none batched.
- C12 Implementation selects/prices verdict API, plan asserts nothing: CONFIRMED + first answer — Phase-0 selected per-packet sendmmsg batching (pkg/nfqueue/nfqueue.go:390-466 VerdictBatch; nfqnlMsgVerdictBatch=3 const :82 unused by batch path — no kernel cumulative semantics). Cluster pricing open.

### S3 Shipped work

- C13 #8276/#8604 instrument, kernel half unpriced: CONFIRMED + progress — b2 header NOT measured still true for real-SA half; but M1/M2 price synthetic NFQUEUE transport + TUN-write leg (measure_stages_test.go:24; measure_memory_test.go:26,115-157). So TUN-write unmeasured is FALSIFIED for synthetic scope, still true for cluster scope.
- C14 #7167 anti-AF_XDP case: CONFIRMED — docs/research/7167-tunnel-ingress/ + server/README.md:254-289.
- C15 #8274 owned-frame + #6682 guard: CONFIRMED — userspace-dp/src/afxdp/wg/decap.rs:168 worker try_decap→build_logical_ingress_packet; policy.rs:174-175,3254 + policy_tests.rs:7572.
- C16 #7949 snapshot visibility: CONFIRMED — secure_tunnel_bind_only_7949.go:96.
- C17 #7191/#5275 unarmed-only barrier; load-bearing bypass: FALSIFIED (unarmed-only) — gate+barrier present AND extended by armed fence #10302. Bypass half (armed-open) closed; unarmed-only must be struck.
- C18 #7480 NoRoute-arm denial; permit-all outbound residual out: CONFIRMED — forwarding/mod.rs #7480 arm; learned_route_cap_8355.go:90-93. No closure of permit-all residual found.
- C19 #7497 per-interface queues: CONFIRMED — planning.rs per-interface min(rx_queues,16); BindingQueuesPerIface; ingress_exclusions.go:336-338.
- C20 #9646 local-address capacity gate: CONFIRMED — maps_sync.go:303-304,968-970 checkLocalAddressCapacity.
- C21 buildDesiredLocalAddressSets feeds userspace_local_v4/v6: CONFIRMED — maps_sync.go:1084 + :967-970.

### S4.2 Transport / commit table / lifecycle

- C22 Divert rules exact; oif==stN untouched; SNAT/accept_local; #7409 reinject: PROPOSAL-UNBUILT (divert) / CONFIRMED (supports) — no iifname==stN queue rules; P_divert absent (zero hits). Supports: SNAT retains XDP ingress identity via XDP pinholes (docs/log/10302.md; daemon_run_bringup.go:676-677 accept_local); #7409 importer live (pkg/routing/fibimport.go:16) + delta #7437 event-driven republish (daemon_route_listener.go:16-23).
- C23 Refuted object = unconditional policy-DROP chain; divert carries no verdict: FALSIFIED (overtaken) — master HAS unconditional DROP (unarmed #7191) + policy-DROP fence (armed #10302). Fence IS a policy-DROP chain; divert must layer WITH it.
- C24 Terminal rule from Packet.Verdict/Queue.VerdictBatch (uncertain never retried, no late ACCEPT): CONFIRMED (now code) — nfqueue.go:331-380 + :390-466: done CAS, ErrAlreadyVerdicted, attempted/successful/uncertain counters. Names match r5 exactly.
- C25 NFQUEUE supplies no generic per-packet timeout: CONFIRMED — ErrTimeout Recv-deadline only, hold unaffected (nfqueue.go:59-61).
- C26 Supervisor 50ms/T_tick/70ms; emission gate + lease: CONFIRMED-UNBUILT — no supervisor/gate/lease on master.
- C27 Route re-resolve at commit; detect-some-and-drop: CONFIRMED-UNBUILT + delta — no commit path; #7437 improves freshness, restore races still undetectable.
- C28 Queue allocator/quarantine/epoch + nft atomic swap at P_divert: CONFIRMED-UNBUILT + M3 note — no allocator/epoch (fixed IDs); P_divert absent. M3 pins source-release behavior (measure_teardown_test.go:10-79).
- C29 Integration via writeTransitGateLocked/reassertTransitGate under transitGateMu; bare callers gone: CONFIRMED — transit_gate_tick_9725.go:63-104; daemon_system.go:992-993; daemon_apply_dataplane.go:178,1210. No bare writers; writeTransitForwardSysctls gate-owned.
- C30 Epochs from one snapshot-generation counter (Q3); monotone bumpGeneration: CONFIRMED (counter) / UNBUILT (queue epochs) — manager_generation.go:49; protocol.go:544-545; flow-cache pair validation. Mechanism available, unbuilt.
- C31 Per-tunnel queues; tunnel max 32; over-max tunnel down: CONFIRMED-UNBUILT.

### S4.3 Handoff pipeline

- C32 Double-buffered in-flight ≥2; bounded verdict queue; capture never blocks; per-flow FIFO + sole lock; fragment pool: CONFIRMED-UNBUILT. Prototype: fragment pool ErrFragmentCapacity (measure_memory_test.go:168-175).
- C33 Pooled slabs; rows (slot,len); 4096/16384 bounds: CONFIRMED-UNBUILT / CONFIRMED (bounds) — b2 PooledCmd{slot,len}; slowpath.rs:703 sync_channel(DEFAULT_QUEUE_DEPTH); worker 4096 per b2 header.
- C34 Owner-homogeneous sub-batches; clock from original capture; mixed-batch single-worker prohibited: CONFIRMED-UNBUILT + M1 note — M1 batch-8-affinity (measure_stages_test.go:41,181).
- C35 Flow-owner record + per-flow-lock transfer: CONFIRMED-UNBUILT.

### S4.4 Adjudication entry

- C36 #8274/#8062 owned-frame before flow-cache/session/policy on tunnel logical ifindex + zone: CONFIRMED (pattern) / UNBUILT (IPsec entry) — logical_ingress.rs:79 used by gre.rs:923 + wg/decap.rs. No IPsec entry — still the gap.
- C37 ARPHRD_NONE L3-offset: CONFIRMED — forwarding/tests.rs:4977; types/forwarding.rs:708-709; main_tests.rs:5524.
- C38 17-field binding threading + fairness bound: STALE-UNCERTAIN — enumeration not located cheaply; needs worker_queue.rs read.
- C39 Worker-verified checksums; GRO/GSO refused-and-counted: CONFIRMED-UNBUILT — no IPsec entry; no GRO-refusal capture cell.

### S4.5 Re-entry TUNs

- C40 One TUN per (worker,instance); W×I≤128; 32-tunnel bound: CONFIRMED-UNBUILT + #10391 delta — no r5 TUNs; but xpf-usp0 + xpf-usp1 multi-queue (q0 marked/q1 unmarked) + TC classifier live (slowpath.rs:31-35,111-118,974-997,1083-1166) + AdjudicatedTransitMark 0x58465001 (transit_barrier.go:26). S4 choice set must add reuse-vs-new-TUN-vs-new-pinhole.
- C41 TUN refused-dataplane class, listed, never in shim ingress map: CONFIRMED-UNBUILT — usp0/1 helper-created (no snapshot rows; refused index N/A). TunSink xpf9506 measurement-only unlisted (tunsink.go:28-45). New TUNs still need refused+fence treatment.
- C42 TTL +1; DSCP; no SO_MARK claim: CONFIRMED (absence) — headers disclaim SO_MARK-on-TUN (tunsink.go, nfqueue.go pkg doc); SO_MARK hits RPM-only. Caution: #10391 TC queue→skb-mark is NOT SO_MARK.
- C43 Single writer per TUN; nonblocking; EAGAIN/short/ambiguous uncertain-terminal: CONFIRMED-UNBUILT + prototype — TunSink O_NONBLOCK + EAGAIN/short errors (tunsink.go:44-70).
- C44 S4 hook/conntrack inventory + isolated zone/VRF; unproven DROP: CONFIRMED-UNBUILT — no re-entry inventory; BPF conntrack mirror covers AF_XDP sessions only (publish_conntrack.rs).

### S4.6–S4.7, S5–S9

- C45 Shadow→drain→enforcing; source-cutoff ack; phase tuple; cancel-beats-ACCEPT; quarantine; class-stickiness: CONFIRMED-UNBUILT.
- C46 S4.7 No unconditional armed DROP chain: FALSIFIED (overtaken) — armed fence exists (transit_barrier.go:140-150); strike prohibition, layer divert with fence.
- C47 No AF_XDP on xfrmi; no AF_PACKET; no userspace ESP; no selector-as-policy: CONFIRMED — exclusion intact; no AF_PACKET capture; kernel XFRM decrypts; traffic-selector gates are commit-validation (compiler_ipsec_trafficselector.go).
- C48 S6.8 fragment contract (v6 overlap-drop, exact-duplicate tuple, atomic-domain, v4 retained-set, 8MiB/tunnel, sweep quota): CONFIRMED-UNBUILT + #9950 delta — no NFQUEUE reassembly; existing fragment_overlap/ screen tracker (#9950 F-035) must be reconciled by S6.
- C49 S6.9 total budget R_box + caps: CONFIRMED-UNBUILT + M2 note — M2 RSS/cgroup/slab/Go-alloc accounting.
- C50 S6.10 inner-L3 counters; attempted vs forwarded; limitation counters: CONFIRMED-UNBUILT + stats note — QueueStats Held/Accepted/Dropped/Attempted/Successful/Uncertain (nfqueue.go:113-128).
- C51 S6.12 resolve_ifindex totality; (0,0) impossible by test: STALE-UNCERTAIN — resolve_ifindex returns Option (fib.rs:552-560); (0,0) fallbacks EXIST (fib.rs:487,511). Cited test not located; claim underspecified vs current code.
- C52 S6.13 ownership-keyed divert oracle (SecureTunnelNetdevForRef ∪ liveXfrmNetdevs); T18: CONFIRMED (oracle) / UNBUILT (divert) — snapshotSecureTunnel union (interfaces.go:856); divert+T18 unbuilt.
- C53 S6.16 input-twin match-set lifecycle: CONFIRMED-UNBUILT (oracles live per C20+C21).
- C54 S8 T12[P] gate-helper integration: CONFIRMED — per C29.
- C55 S10 Q3 counter+lease; Q7 scope sufficiency: CONFIRMED (counter per C30) / OPEN (Q7 harder — T12 must cover fence+divert coexistence, two writers one FORWARD hook; S3 spike).

### S12 adjudication rows + N-clauses (codebase facts inside)

- C56 N3 contract does not deny NFQA_TIMESTAMP: CONFIRMED — parseOnePacket reads hdr+payload only; recvTime=now (nfqueue.go:636-672).
- C57 B-row M3-class source-release pin: CONFIRMED — measure_teardown_test.go:10-79 (held unobservable after release; ErrClosed after close).
- C58 S3.4 nft transaction at P_divert; production uses gate helpers: CONFIRMED-UNBUILT (transaction; P_divert absent) / CONFIRMED (helpers per C29).

## Top 5 load-bearing deltas (ranked)

1. Threat model inverted by #10302 (+#10391). S1 deliberately open now policy-DROP + pinholes (C04/C06/C23/C46 falsified). Live gap: (a) INPUT/host-bound decrypted ingress, (b) marked-usp1 residual semantics, (c) fail-closed-but-unadjudicated DROP. Re-plan S1, S4.2 layering, S4.7, S8 G2/T12. Divert must order against fence filter-priority DROP — S3 first spike.
2. S4 choice partially preempted by #10391. Queue-index → TC classifier → skb-mark → fence-mark-pinhole is a shipped mechanism answer. r6 chooses: reuse marked-queue pattern vs new TUNs+new pinholes vs VRF/policy-routing. S12.5 items 5-6 need re-sign.
3. Phase-0 transport exists. pkg/nfqueue (sendmmsg VerdictBatch, terminal accounting matching r5 names, TunSink, M1/M2/M3) answers verdict-API selection and synthetically prices stages+memory+TUN-write+teardown (C12/C13). S1/S5 and S2/S8 re-baseline on M1/M2/M3; cluster gates remain.
4. Advisory prose + fence/divert layering undesigned. compiler_ipsec_plaintext_warn.go:102-104 still says kernel-forwarded; T12 scope must expand to fence+divert coexistence (two writers, one FORWARD hook, bridge+inet). S3 owns both.
5. Dependency surface intact + absorbable deltas. SecureTunnel union, buildDesiredLocalAddressSets+#9646, bumpGeneration, #6682, #7949, #7497, build_logical_ingress_packet (#8062/#8274), #7480 all CONFIRMED. Absorb: #7437 (fresher FIB), #9950 (overlap tracker — S6 reconcile), #10308 (checked, NO impact: divert iifname-keyed, exclusion class-keyed, neither consults zone names).

## r6 recommendation: TARGETED RE-PLAN (not rewrite, not kill)

Re-plan: S1 (threat + residual-gap statement), S4.2 (divert + fence layering: priority/table/chain, bridge leg), S4.5/S4 (re-entry choice vs #10391 precedent; pinhole vs VRF), S4.7 (strike no-armed-DROP), S8 G2/T12 (fence-aware chain-presence + scope), S12.5 items 5-6 (re-sign), advisory wording fix (compiler_ipsec_plaintext_warn.go:102-104) as pre/co-requisite. Retain: commit table + terminal accounting (code-backed C24), NFQUEUE choice (prototype-backed), shadow phasing, T22 shape (re-baselined on M1/M2), fragment contract (reconcile w/ #9950), S12.3 clauses, S1/S2/S5-S8 skeleton. Kill only if: owner refuses re-sign, or S3 fence+divert coexistence spike proves unworkable (no placement admits divert-before-fence on both families without reopening leave-alone transit).

## S12.5 sign-off validity

- 1 route contract (detect-some-and-drop): HOLDS — still only honest claim; #7437 helps freshness; reconfirm cheaply.
- 2 overload class: HOLDS — untouched by drift.
- 3 T22 polarity: HOLDS — M1/M2 synthetic baselines, not renegotiations; G2 chain-presence must now include fence table.
- 4a-4d deadline value/split/cancellation/cliff: HOLD — no supervisor on master; nothing drifted.
- 5 re-entry metadata (topology/VRF-or-DROP): NEEDS RE-SIGN — #10391 shipped a mark-based alternative the sign-off did not contemplate.
- 6 topology (dedicated instance per VRF/RG, no-main-transit): NEEDS RE-SIGN — mark-based isolation precedent may obsolete instance-per-VRF.
- 7 terminal accounting: HOLDS (strengthened) — implemented in pkg/nfqueue (C24), now code-backed.

## STALE-UNCERTAIN list (6, each with cheap next check)

- C07 (2,797ns derivation): read #8276 pricing artifacts, 10 min.
- C08 (111ns recorded values): run cargo bench --bench b2_capture_bridge on loss cluster, 30 min (not a lane task).
- C38 (17-field binding): read worker_queue.rs WorkerCommand + diff vs r2 S4.4, 15 min.
- C51 (resolve_ifindex totality test): locate r2-cited test in forwarding_build tests, 15 min.
- Merge SHAs for #10302/#10308/#10391: needs git log; parent fills from docs/log/10302.md, 10308.md, 10391.md + git log --grep.
- b2 bound literals (4096/16384) vs live consts: grep MAX_PENDING_WORKER_COMMANDS + DEFAULT_QUEUE_DEPTH, 5 min.
