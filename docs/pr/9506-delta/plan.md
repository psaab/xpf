# 9506 delta plan: ship P-MECH permits on the current master (research/9506-delta)

- Review state: **v5 revision; parent re-dispatch pending; this worker assigns
  no final PLAN-READY/PLAN-KILL verdict.** Round four at `5f97823bb` returned
  3-of-3 NEEDS-MAJOR, converging (finality rule, coordinated CAS, ack
  structure credited) with no further slice-time deferrals accepted. This
  revision closes every residual with implementable mechanisms: typed
  `IoRelease` correlation + durable obligation store; chosen reaper owner,
  deadlines, lag bound, ceiling constants, and quarantine preinstall; the
  enforced receive-mode downstream invariant; FRR render-gate authority +
  semantic refused set; drain-then-effective M3 revocation with a named
  rendezvous; periodic RPDB audit + synchronous FIB fence; allocated reason
  bytes; chosen ack wire; and corrected scope symbols. The parent will
  re-dispatch the blinded gate against this committed revision.
- Date: 2026-09-27. Worktree `/var/tmp/worktrees/9506-research`, branch `research/9506-delta`.
- Pins: `origin/master = 028c4e4e2` (assessed); Sep-20 code tip `b71c52d60`
  ("pmech: land deny-only D11 bridge (#9506) (#10483)"); Sep-20 design tip
  `ebcec7ad4` (`research/9506-pmech-design`, `docs/pr/9506-xfrm-capture/pmech-design.md`,
  2264 lines); r6 plan `b4f1d3035` (`research/9506-reground`).
- Authority: read-only on source; this doc is the only writable path
  (`docs/pr/9506-delta/*.md`). No PR from this branch. Never merge.

## 1. Status

The Sep-20 work is **fully landed, not stranded**. There is no rebase to perform
and no branch-only behavior to adopt:

- `fix/9506-mech` tip `35a0b7e1a` is tree-identical to landed `b71c52d60`
  (re-verified this run: `git diff b71c52d60 35a0b7e1a --quiet` → identical;
  the branch itself is deleted, the tip commit object remains). The Sep-24
  "rebase collides on commit 1 across 4 files/28 markers" is replaying
  already-landed content. Do not rebase it.
- S-F1 (divert-absent-window INPUT exposure) landed via #11107 (`19eb3e436`,
  on master): removal/shutdown/rollback now hold → verify → remove → retire
  with generation-bound CLOSING holds, exact nft readback, ambiguous-removal
  quarantine fallback, A1–A5 cells.
- Master since Sep-20 is a **deny-only + shadow** data plane with the full D11
  verdict/attestation/counter/witness substrate. The original defect's
  enforcement half is still open: no production policy-permit/q0-write join
  exists on the diverted path (see §4 absence proofs).

Remaining slice order (from the Sep-25 delta assessment, still current):
**P1 → P2 → V1(structural) → P3 → V2**. F1 is done. P2 is the issue-closing
slice; V2 is the pricing-gate proof. #9506 stays OPEN until P2+V2.

## 2. Framing

### Threat model (post-#10302, already folded into r6/P-MECH)

The issue body was written against a fail-open-forward kernel: armed state
removed the transit barrier while `ip_forward=1`, so decrypted xfrmi ingress
was kernel-forwarded with no zone policy. #10302 inverted S1 to
fail-closed-drop: `applyTransitBarrier(true)` now installs an armed forward
fence (`InstallArmedTransitFence`, policy DROP with provenance-scoped pinholes)
instead of removing the barrier (`pkg/daemon/daemon_transit_gate.go:421-457`,
`pkg/nftables/transit_barrier.go`). The fence spec comment is explicit:
"Direct route-based IPsec plaintext arrives on its daemon-owned xfrmi and
remains absent from the allowlist; kernel-XFRM reinjection instead arrives
through the marked xpf-usp1 queue" (`daemon_transit_gate.go:113-124`).

Consequence of the inversion: the live defect is no longer "peer inner packets
reach internal destinations with no policy" but "ALL diverted decrypted-ingress
drops, including legitimate flows" — a fail-closed availability gap plus
missing policy/session/counter/HA/MTU evidence. The r6 delta memo (Sep-19,
`c4f664191`) already regrounded the plan on this model, and the P-MECH design
(§6 threat-model delta vs r6 S1) targets the residuals. The inversion re-scopes
the mechanism (restore permitted flows through adjudication + marked reinject);
it does not retire it.

### Owner chain (no open owner except #9506)

- #7167 CLOSED NOT_PLANNED (umbrella): closing comment "Not closing because
  the gap is fixed — it is not." Split into #8274 (WireGuard, shipped) and
  #8276 (IPsec).
- #8276 CLOSED COMPLETED via #8604: "a pricing task first and an
  implementation second ... lands no production code." Kernel half explicitly
  unpriced ("needs a box where XFRM SAs and netfilter can be driven against
  real traffic").
- #7949 CLOSED: egress-half visibility only; the advisory narrows itself to
  INGRESS (`compiler_ipsec_plaintext_warn.go:100-114` in the issue's reading).
- #9506 OPEN and named owner since #9602 (repointed refs + census guard
  `pkg/refactoraudit/closed_owner_8276_9506_test.go`). Acceptance unchanged:
  denied AND permitted IPv4/IPv6 decrypted-ingress flows with policy/session/
  counter evidence, HA + MTU behaviour, pricing gate (same-thread ~111ns or
  batched B>=3).

### Scope / non-goals

- In scope: P1 session discriminator, P2 FORWARD permit join, M1–M4
  must-proves, conditional P3 D12a-Option-A stateless INPUT, V1/V2 flips.
- Non-goals: D12a Option B (stateful INPUT atomicity proof — deferred/
  unauthorized); duplicating ESP decryption in userspace (refuted, XFRM stays
  crypto authority); AF_XDP bind on xfrmi/B1 (refuted on four independent
  grounds); nftables `hook forward` while armed outside the fence model
  (refuted); re-litigating B2 economics without loss-cluster numbers.
- Closure boundary: stateful INPUT is out of the proposed #9506 acceptance
  only if the issue owner signs off before P2 lands. No such sign-off is
  claimed here; without it, P2 cannot be called issue-closing.

## 3. Prior-work inventory (branches + commits + docs)

| Artifact | State | Content |
|---|---|---|
| `origin/research/9506-xfrm-capture` @ `477be227f` | superseded by r6 | plan.md r1→r4 + 8 raw reviews; GLM PLAN-READY vs Codex NEEDS-MAJOR split → Phase-0 measurement call |
| `origin/research/9506-reground` @ `b4f1d3035` | design basis | `r6-delta.md` (58 claims: 41 confirmed/11 falsified/6 uncertain) + `r6-plan.md` (2111 lines); r6 PLAN-READY both reviewers, 0 open items |
| `origin/research/9506-pmech-design` @ `ebcec7ad4` | **canonical mechanism design** | `pmech-design.md` (2264 lines): G1–G6, S9.1–S9.7, E1–E37, M1–M4, D5c, D12a-A authorized/B deferred, §5.2 file list, §5.6 mixed-version, §5.7 flip protocol |
| `b71c52d60` (#10483, on master) | **landed Sep-20** | deny-only D11 bridge: 33 files, +7043/−360 (D1b quarantine/nft guard, durable identity, Rust D11 transport, 26B tail, Deny/WouldPermit-10 join, protocol 29) |
| `35a0b7e1a` (`fix/9506-mech` tip, branch deleted) | landed-content duplicate | tree-identical to `b71c52d60`; nothing to adopt; do not rebase |
| `origin/fix/9506-vpn-ingress` | Phase-0 evidence | `cb752957a` NFQUEUE transport measurement + evidence doc (B2 kernel-half input) |
| `origin/fix/9506-f1`, `origin/fix/9506-sf1-fence-removal` | landed via #11107 | fence-before-removal; superseded by `19eb3e436` on master |
| `docs/log/9506*.md` (9 files on master) | live record | mech/observe/oprov/s3/s4/s5/fixture/counter logs; observe ledger 30/30 VOID |

Sep-24 "rebase aborted" post-mortem: there was never anything to rebase. The
+14 `fix/9506-mech` commits ARE the squash content of #10483; collision on
replay is expected. No stranded work, no lost commits (tip object verified
present and identical).

## 4. Drift: Sep-20 → master (`b71c52d60..028c4e4e2`), per touched file/symbol

### 4.1 b71c52d60 file set: churn summary

24 of 33 files changed since the bridge; 9 are unchanged. This census is the
complete file set from `git diff-tree --no-commit-id --name-only -r b71c52d60`,
compared with `origin/master` at `028c4e4e2`. Changed-file counts and latest
commit identifiers below come from `git log b71c52d60..origin/master -- <path>`.
No file was deleted or renamed.

| Sep-20 touched path | Drift since `b71c52d60` (count; latest commit) | Resulting constraint |
|---|---|---|
| `docs/log/9506-mech.md` | unchanged (0) | Sep-20 evidence record remains byte-stable. |
| `pkg/config/xfrmi.go` | unchanged (0) | `BindInterfaceOwnsRef` basis is unchanged. |
| `pkg/daemon/ipsec_capture_identity_9506.go` | unchanged (0) | Durable capture identity unchanged. |
| `pkg/daemon/ipsec_capture_pipeline_9506.go` | 2; `5312ec41d` D11 re-attestation | Recheck attestation wiring before generalizing its one-shot path. |
| `pkg/daemon/ipsec_capture_wiring_9506.go` | 7; `19eb3e436` F1 removal recovery | Authority split, re-attestation, and F1 hold/readback lifecycle are live; F1 is done. |
| `pkg/daemon/ipsec_capture_wiring_9506_test.go` | 8; `19eb3e436` F1 tests | New transition/readback/rollback tests cover F1; do not re-open that slice without a reproduced gap. |
| `pkg/dataplane/userspace/learned_route_cap_blackhole_9054_test.go` | 1; `53bf0a635` protocol-v30 pins | Test-only version-pin follow-up; current v35 lockstep supersedes its literal floor. |
| `pkg/dataplane/userspace/protocol.go` | 8; `216c99be8` protocol v35 | Go wire contract now v35; P1 adds a lockstep version/floor, never reuses v29/v30. |
| `pkg/dataplane/userspace/secure_tunnel_protocol_6691_test.go` | 7; `216c99be8` protocol v35 | Test-only mixed-version/secure-tunnel floor drift; update its expectations with P1. |
| `pkg/dataplane/userspace/snapshot_shape_version_8892_test.go` | 7; `216c99be8` protocol v35 | Test-only shape/version expectations; P1 must update the lockstep contract. |
| `pkg/dataplane/userspace/testdata/contract-9821-declared-snapshot.json` | 6; `216c99be8` protocol v35 | Snapshot fixture drift only; refresh fixture for any added tunnel identity field. |
| `pkg/nfqueue/nfqueue.go` | 2; `1e40f3542` linuxsock | Socket creation now uses `linuxsock`; bounded verdict send/lock semantics remain a P2 re-ground. |
| `pkg/nfqueue/nfqueue_protocol_test.go` | unchanged (0) | Existing protocol tests are byte-stable; add P2 completion cases at current behavior. |
| `pkg/nfqueue/pipeline.go` | 4; `18c7ac658` fragment expiry/accounting | Accepted-vs-capture authority, D11 selector, event gating, and fragment lifetimes changed; re-derive G3/fragments and the permit arm. |
| `pkg/nfqueue/pipeline_9506_test.go` | 4; `18c7ac658` fragment accounting | Test-only fragment expiry/accounting coverage; preserve it when adding fail-on-revert permit cells. |
| `pkg/nfqueue/reinject_socket.go` | unchanged (0) | Submit/completion socket substrate unchanged since the bridge; still needs P2 identity/join extension. |
| `pkg/nfqueue/reinject_socket_9506_test.go` | unchanged (0) | Existing completion tests are stable; add commit/uncertain/no-retry contract cells. |
| `pkg/nftables/ipsec_divert.go` | 1; `fec7d18a3` loopback exemption | Quarantine now has a loopback exemption; include it in the armed-fence/bypass audit. |
| `pkg/nftables/ipsec_divert_identity_9506.go` | unchanged (0) | Durable quarantine identity implementation unchanged. |
| `pkg/nftables/ipsec_divert_test.go` | 2; `eadc3a6a0` loopback family matrix | Test-only inet/bridge loopback matrix added; retain as guard while permit rules evolve. |
| `userspace-dp/src/afxdp/coordinator/mod.rs` | 9; `0a9dae296` directed-broadcast neighbor refusal | Coordinator changed since D11 wiring; re-ground P-MECH module/startup composition rather than transplanting Sep-20 imports. |
| `userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs` | 7; `e169bcf26` ARP-cache anti-replacement | Bring-up/reconcile path changed; verify queue publication and fail-closed readiness against current ordering. |
| `userspace-dp/src/afxdp/ipsec_inner.rs` | 1; `1838aaf59` 12-counter snapshot | Counter export landed; Go decode (`protocol_status.go:771-789`) and Prometheus descriptors are also present, so the counter follow-up is done. |
| `userspace-dp/src/afxdp/ipsec_inner_queue.rs` | unchanged (0) | 2017-line bounded D11 queue transport remains unchanged. |
| `userspace-dp/src/afxdp/mod.rs` | 15; `d06a7c2bd` secondary-deny app resolution | AF_XDP module wiring/policy consumers evolved; re-ground integration imports and app/policy stage assumptions. |
| `userspace-dp/src/afxdp/types/runtime_view.rs` | 1; `c44a97206` tunnel rows through snapshot paths | Tunnel-row publication changed; D13 must bind to current immutable tick view and accepted/capture authority. |
| `userspace-dp/src/afxdp/worker/loop_body/mod.rs` | 12; `0ce15ecb5` source quota/RSS changes | Worker loop now has quota/RSS changes; re-check poll-budget fairness, per-worker drain, and one-view-per-tick claims. |
| `userspace-dp/src/protocol/control.rs` | 11; `216c99be8` protocol v35 | Rust handshake now v35 and remains exact-equality; P1's control and Go versions/floors must move in lockstep. |
| `userspace-dp/src/server/reinject_9506_tests.rs` | 1; `7bafffd82` completion-ACK test | Test-only completion ACK synchronization added; P2 must preserve its timing/ownership contract. |
| `userspace-dp/src/slowpath.rs` | 2; `b157b8e23` TUN-dependent sweep-test gate | Production also has SA-gated stage-11 passthrough (`3eaf618fc`); `submit_ipsec_inner_v1` still only admits transport, no verdict→q0 join. |
| `userspace-dp/src/slowpath_reinject_9506.rs` | 1; `5312ec41d` attestation | Narrow D11 attestation join landed; ordinary-flow permits remain absent. |
| `userspace-dp/src/slowpath_reinject_9506_tests.rs` | 1; `5312ec41d` attestation | Test-only attestation coverage; does not prove general permit/session/NAT behavior. |
| `userspace-dp/tests/runtime_view_publish_canary.rs` | unchanged (0) | Publisher canary unchanged; still useful for the D13 no-extra-view-load contract. |

Thus 24 changed + 9 unchanged = all 33 Sep-20 commit paths. The change classes
are not uniform: protocol/test fixtures moved through v35; NFQUEUE fragment and
authority behavior changed; worker/session/policy code had substantial unrelated
security hardening; D11 counters and F1 were added. The affected consumer
contracts are called out per path above, not treated as a mechanical rebase.

### 4.2 Canonical P-MECH §5.2 design-path census

The design names further paths beyond the 33-file D11 commit. This second census
covers every Go/Rust production path named in its §5.2 file list. Counts are
post-bridge commits through `028c4e4e2`; the listed latest commit is exact evidence
of the most recent file drift, not a claim that intervening changes are absent.

| Planned P-MECH path | Drift (count; latest) | P-MECH impact / current finding |
|---|---|---|
| `pkg/nfqueue/pipeline.go` | 4; `18c7ac658` fragment expiry/accounting | `submitEligible` records `V1PermitSuppressed` and calls `finishFrame(..., VerdictDrop)` for `ZonePass` (`:665,743-745`); `resolveCompletion` terminal-DROPs the held original after normal, uncertain, and WouldPermit outcomes (`:975,1081-1093`). P2 must preserve this single q0 forwarding path. |
| `pkg/nfqueue/nfqueue.go` | 2; `1e40f3542` linuxsock | `VerdictAccept` means NF_ACCEPT (`:45-47`); `Queue.VerdictBatch` can release held originals (`:519`). Do not combine that with a q0 write for the same frame. |
| `pkg/daemon/ipsec_capture_pipeline_9506.go` | 2; `5312ec41d` D11 re-attestation | `IpsecCapturePipelineStatus.DeliveredAvailable/Delivered` is a witness (`:59-70`); `MintLeaseForAttest` is explicitly `attest-`-scoped (`:500`). Neither is a production policy-permit join. |
| `pkg/daemon/ipsec_capture_wiring_9506.go` | 7; `19eb3e436` F1 | `buildPMechZoneSnapshot` and `samePMechTunnelZones` establish the immutable tunnel-zone view (`:229,336`); `tunnelRowsSnapshot` publishes the current rows (`:419`). Reuse the accepted/capture-generation and F1 hold lifecycle. |
| `pkg/nfqueue/reinject_socket.go` | 0; unchanged | `SubmitAdjudicated`, `DrainReinjectCompletions`, and `AnnounceReinject` are the existing submit/result/authority surface (`:115,149,245`); P2 must extend the terminal permit join, not invent a second transport. |
| `pkg/routing/routes.go` | 1; `fbb21f67a` bounded routing responses | `RouteEntry`/`NextHop` retain ECMP legs (`:35,45`); `GetAllTableRoutes` and `multiPathNextHops` expose routed tables/legs (`:253,350`). This is an inventory input, not a q0 egress-domain proof. |
| `pkg/routing/routing.go` | 2; `b4170c6d5` startup probe cleanup | `Manager.GetAllTableRoutes` and `ApplyNextTableRules` are the current table/rule entry points (`:184,223`); no `xpf-usp1` exclusion exists in `pkg/routing` (negative grep). P2 must prove RPDB non-steering or refuse the conflicting configuration. |
| `pkg/daemon/ipsec_reinject_supervisor.go` | 0; unchanged | `tryOpenPermit` and `commitValidatedVerdict` own the S4 permit and terminal verdict transaction (`:342,606`); there is no P-MECH q0 `InputPermitCommitter` here. Extend the owner, not a parallel opener. |
| `pkg/daemon/ipsec_topology_owner_9506.go` | 0; unchanged | `noteIpsecTopologyLinkTransition` and `pollIpsecTopology` track F1 link/permit transitions (`:131,152`); no P-MECH flip authorizer exists. P2 must bind its transition to the same owner/epoch. |
| `pkg/daemon/ipsec_host_fence_reconcile_9506.go` | 2; `19eb3e436` F1 | `ipsecHostInputFenceOverlayForPermit` and `tryOpenIpsecPermitAfterFenceAck` implement the F1 fence-aware OPEN path (`:25,109`). Reuse this predicate; it is not a P-MECH q0 commit proof. |
| `pkg/daemon/ipsec_supervisor_loop_9506.go` | 0; unchanged | `startIpsecSupervisorLoop` starts the S4 supervisor and topology watch (`:15-30`); there is no separate P-MECH generation guard in the loop. |
| `pkg/api/metrics_ipsec_capture_10478.go` | 1; `5312ec41d` D11 re-attestation | `collectIpsecCaptureWitness` exports capture/D11 actor and delivered-witness fields (`:14,42-64`); it does not witness production policy permits or q0 egress. |
| `pkg/config/xfrmi.go` | 0; unchanged | `BindInterfaceOwnsRef` is the bind/interface ownership predicate (`:296-297`); preserve its exact ownership semantics when deriving tunnel rows. |
| `pkg/ipsec/policy.go` | 8; `4029db268` refresh changed tunnels | `effectiveTrafficSelectors` and exported `EffectiveTrafficSelectors` define selector provenance (`:600,737-738`). Re-ground refresh/generation handling before using selectors as source admission. |
| `pkg/logging/ringbuf.go` | 2; `cf39f563a` stale POLICY_DENY attribution | `eventTypePolicyDeny` and `policyDenyConfigGeneration` define the current reason/generation decode path (`:141,154-162`); existing reason constants end at host-inbound. G4 must add/round-trip any P-MECH reason through this path, not assume an event family. |
| `pkg/nftables/ipsec_divert.go` | 1; `fec7d18a3` loopback quarantine exemption | `IpsecQuarantineTableName`, priority, and closed `IpsecQuarantineReason` set describe the D1b staged guard (`:19-61`). Preserve loopback exemption behavior and prove the guard’s transition/ACK before relying on it. |
| `pkg/dataplane/userspace/protocol.go` | 8; `216c99be8` v35 | `ProtocolVersion=35` (`:359`) mirrors Rust; `IpsecTunnelRowSnapshot` and `IpsecTunnelRows` carry `{stn, if_id, logical_ifindex}` (`:664-691`). There is no `MinProtocolPMech` floor; P1 must add the per-feature exact-equality contract for its new wire tag. |
| `userspace-dp/src/protocol/control.rs` | 11; `216c99be8` v35 | `CONFIG_SNAPSHOT_PROTOCOL_VERSION=35` (`:215`) mirrors Go; `S5ReinjectStatus` mirrors Go reinject status (`:489,544`). No P-MECH session-discriminator floor is present. |
| `userspace-dp/src/protocol/snapshot.rs` | 4; `0722b51f7` SYN-admission selectors | `IpsecTunnelRowSnapshot` and `ipsec_tunnel_rows` carry current row identity (`:501,541`), alongside generation-bound snapshot semantics. P1’s protocol change must keep both serialized row shape and Go/Rust equality in lockstep. |
| `userspace-dp/src/afxdp/ipsec_inner.rs` | 1; `1838aaf59` counter export | The module contract says the final V1 join is deny-only with no q0 enqueue or NF_ACCEPT (`:3-7`); `adjudicate_descriptor` is the worker decision entry (`:394`). P2 needs a new explicit permit outcome and join. |
| `userspace-dp/src/afxdp/ipsec_inner_queue.rs` | 0; unchanged | `IpsecInnerDescriptor` and `IpsecInnerVerdict` define the bounded request/result types (`:145,183`); `try_enqueue`/`close_and_drain` enforce bounded admission and retirement (`:488,512`). No production Permit variant exists. |
| `userspace-dp/src/afxdp/poll_descriptor/mod.rs` | 60; `ec59234a1` fragment lifetime hardening | The ordinary packet path calls `evaluate_policy_result_with_icmp` at TWO consult sites (`:3992` and `:7645`); fragment/policy order changed materially. Re-derive G3 consult order at P2 from both sites; do not transplant the D11 worker entry into this path blindly. |
| `userspace-dp/src/afxdp/logical_ingress.rs` | 0; unchanged | `build_logical_ingress_packet` is the shared logical-frame synthesis/reparse helper (`:79`), already called by `ipsec_inner.rs:289`; keep one canonical path with explicit inputs. |
| `userspace-dp/src/slowpath_reinject_9506.rs` | 1; `5312ec41d` attestation | `ADMIT_INPUT_HOOK=6` and `ADMIT_TUNNEL_ROW_MISSING=12` remain closed (`:51,54`); `resolve_ipsec_inner_verdict` maps success only to `WouldPermit`, explicitly never q0/NF_ACCEPT (`:1103-1118`). P2 needs a distinct q0-written terminal join. |
| `userspace-dp/src/slowpath.rs` | 2; `b157b8e23` test gating | `submit_ipsec_inner_v1` sends an admitted descriptor to the bounded D11 transport (`:1283-1333`); `submit_adjudicated_frame` selects it (`:1337-1344`). The existing `tx_delegated` writer is separate; join worker Permit to that single writer without NF_ACCEPTing the held original. |
| `userspace-dp/src/session/discriminator.rs` | 0; unchanged | `TunnelDiscriminator` has `None`, `Unkeyed`, `Keyed`, `Pptp`, and `Unparseable` variants (`:27-80`); no `Ipsec(if_id)` variant exists. |
| `userspace-dp/src/session/key.rs` | 1; `b20fab7f2` fragment sentinel | `reverse_direction_discriminator` handles the current classes (`:42-62`), and `SessionKey.discriminator` is part of the key (`:81`); no IPsec identity or cross-class reverse alias is represented. |
| `userspace-dp/src/session/lookup.rs` | 10; `1db98f3c8` SYN-ACK-first bounds | `resolve_lookup_handle` checks the exact primary key then the reverse-translated alias path (`:70-97`); no P-MECH cross-discriminator alias index exists. P1 must preserve current alias multiplicity, validation, and eviction rules. |
| `userspace-dp/src/session/mod.rs` | 14; `0ce15ecb5` source quota/RSS | `SeededReverseIndex`, `SeededForwardWireIndex`, and `SeededReverseTranslatedIndex` are the current alias indexes (`:47-51`); `SessionTable.key_to_handle` is primary (`:1191`) with bounded session/owner accounting. P1 must add its alias under these invariants, not a side map. |
| `userspace-dp/src/afxdp/worker/loop_body/mod.rs` | 12; `0ce15ecb5` source quota/RSS | The worker loads one coherent `RuntimeView`, drains `ipsec_inner_transport` (`:1196-1207`), calls `adjudicate_descriptor` (`:1234`), and drains bounded completions (`:1249-1253`). Preserve this one-view/fairness contract in P2. |
| `userspace-dp/src/afxdp/worker_queue.rs` | 1; `1ec741810` PPTP teardown | `push_bounded` and `WorkerCommand::EnqueueShapedLocal` are bounded worker-control paths (`:528,556`); no IPsec-inner packet command exists. Do not route worker verdicts through an unbounded or second-writer command. |
| `userspace-dp/src/policy.rs` | 10; `f82216100` fragment-deny guard | `evaluate_policy_result_with_icmp` is the production policy evaluator (`:3036`); fragment refusal/order changed after the baseline. P2 should call the existing evaluator and prove current G3 order rather than fork policy semantics. |
| `userspace-dp/src/afxdp/event_emit.rs` | 1; `cf39f563a` deny attribution | Transit and host-inbound denies use `DataplaneEventKind::PolicyDeny` with distinct reason bytes (`:15-21,160-195,217-220`). Add P-MECH deny reasons through this producer if required; no parallel event kind is implied. |
| `userspace-dp/src/event_stream/codec/rt_flow.rs` | 1; `cf39f563a` deny attribution | `DataplaneEventKind::PolicyDeny` maps to the current RT_FLOW wire type (`:14-15,33,43`); reason is emitted at byte 134 (`:541`). Keep any added reason byte compatible with this producer’s layout. |
| `userspace-dp/src/event_stream/codec/decode.rs` | 1; `cf39f563a` deny attribution | `policy_deny_config_generation` is marker-gated (`:29-33`); decoder restores policy ID and reason (`:65-71`). Add a round-trip check for any P-MECH reason/generation extension. |
This is 35/35 design paths; the 33-file code-commit census above is separately
closed. Each path now records its current master symbols (or explicit absence),
not just a generic drift consequence. Core permit gaps follow.

#### 4.2.1 v2 gate-only paths beyond the canonical 35

These additional paths were introduced by the round-one review blockers; they
are not part of the canonical §5.2 35-path count above.

| Additional P2/evidence path | Current symbol evidence at master `028c4e4e2` | Gate implication |
|---|---|---|
| `pkg/routing/rules.go` | `ribGroupLeakRulePriority=30000` (`:64-70`); rib-group rules set Dst/Table/Priority/Family but no IifName (`:675-678`); next-table rules set IifName (`:329-333`); PBR rejects missing IifName (`:937-948`). | M1 must evaluate actual live selector/action/order; PBR/FBF-only refusal is not sufficient. |
| `pkg/nftables/transit_barrier.go` | `TransitFenceDeliveredCounterName` is documented as a downstream-of-TUN witness, not a verdict (`:17-22`); q0 mark/interface conjunction is declared at `:32-43`, counter increments at `:276-280`. | `delivered` proves fence-match only; M2 requires a separate egress-table oracle. |
| `userspace-dp/src/server/helpers/session_sync.rs` | `resolve_synced_discriminator` accepts absent tags as `None` for non-GRE imports, refuses unknown tags, and treats absent/unknown DELETE as `None` (`:100-131`). | P1 must define authority-scoped absent-tag handling for IPsec-inner TCP/UDP while preserving native imports. |
| `pkg/dataplane/userspace/protocol_ha.go` | `TunnelDiscriminator` is carried as opaque u64 and explicitly owned by Rust `session/discriminator.rs` (`:188-225,398-411`). | No Go codec: P1 updates the carrier only if wire shape changes; codec tests live with Rust owner. |
| `pkg/cluster/sync_protocol.go` | HA session values encode the opaque discriminator (`:252-258,422-424`) and decode length-gated values (`:801-804,987-990`). | P1 consumer census includes binary encode/decode, import, delete, and old-peer absence paths. |
| `test/incus/t12-g2-9506.sh` | Local executable defaults to `xpfd` and compares remote running `xpfd` hashes on both nodes (`:2894-2902`); no userspace-dp helper attestation is present there. | O5 requires source-bound manifests plus running hashes for both binaries on both nodes and kernel/classifier identity; wrong/missing artifact is VOID. |


### 4.3 Symbol-level drift (design §5.2 / Sep-25 coverage map vs master)

COVERED (present, cited line numbers drifted only):

- S9.1: `ZoneEvaluator`/`ZoneSnapshotRef`/`ErrNoZoneEvaluator`
  (`pipeline.go:186-197,282`); `buildPMechZoneSnapshot`
  (`ipsec_capture_wiring_9506.go:229`); `submitEligible` (`pipeline.go:665`);
  `BindInterfaceOwnsRef` (`xfrmi.go:296`); `StableZoneID` join (`:286`);
  `QuarantineAll` lifecycle; `tryOpenIpsecPermitAfterFenceAck` +
  `tryOpenPermit` shared OPEN predicate (host-fence reconciler).
- S9.2: `ipsec_inner.rs` + `ipsec_inner_queue.rs`; `ADMIT_OK..ADMIT_TUNNEL_ROW_MISSING`
  (`slowpath_reinject_9506.rs:45-54`); `D_usp1` expected-domain stamp
  (`ipsec_inner_queue.rs:162`); `DOMAIN_OVERLAP`/`OWNER_CONTESTED` (`ipsec_divert.go:88-90`).
- S9.3: worker entry + D13/D14 zone gate (`ipsec_inner.rs:1` header);
  `zone_gate_{unzoned,ambiguous,stale,no_generation}_total`.
- S9.6 partial: `IpsecInnerReason` 5,6,32–60 (`pipeline.go:1509-1541`) incl.
  `ReasonFragmentRefused=54`, `ReasonInputBoundary=59`; `ZoneReason`;
  `D11Deny52` counted only after operator-event delivery (`emitD11Deny`,
  `pipeline.go:607`); zone-only rezone rotates capture generation
  (`samePMechTunnelZones`, wiring `:336`).

ABSENT (still owed — the mechanism; each verified by negative grep this run):

- S9.4: **no `Ipsec(if_id)` variant** — `TunnelDiscriminator` is
  `{None, Unkeyed, Keyed(u32), Pptp(u32), Unparseable}`
  (`session/discriminator.rs:27-80`); zero `Ipsec(` hits in `session/`;
  no `if_id`/`xfrm` hits in `session/*.rs`. P1 pre-req stands.
- S9.5 FORWARD permits: `submitEligible` ends every enforcing arm in
  `finishFrame(…, VerdictDrop)`; even `ZonePass` is `V1PermitSuppressed` +
  drop (`pipeline.go:743-745`). `VerdictAccept` exists only for
  `PipelineShadow` (`pipeline.go:460-484,811-812`). `submit_adjudicated_frame`
  → `submit_ipsec_inner_v1` admits to worker transport only — no
  verdict→`tx_delegated` split, no production policy-permit/q0-write join.
  The D11 attestation arm (`dispatchAttestEligible`,
  `pipeline_attest_10484.go:778-797`) is narrow and selector-armed only;
  ordinary frames stay deny-only. **This is the original defect, still open.**
- S9.5 INPUT (D12a-A): `ADMIT_INPUT_HOOK=6` refusal stands; **no
  `InputPermitCommitter` / `CompletionInputReady` anywhere**; D12a-C1/C2 proof
  cells not run.
- M1: no q0 RPDB non-steering proof. The current fallback is wrong-sized:
  rib-group leak rules carry Dst/Table/Priority/Family with NO ingress selector
  at pref 30000, before main (`rules.go:64-70,675-678`), so PBR-free config can
  still steer q0 off main; ordinary PBR rules are already ingress-scoped
  (`rules.go:939-948`), so PBR presence alone is not proof q0 is steered.
  No in-flight fence exists either: revoke is CAS-only nonblocking
  (`ipsec_reinject_supervisor.go:260-302`), `pre_write_check` flips Queued→
  WriteStarted under a mutex and returns before the TUN write
  (`slowpath_reinject_9506.rs:1041-1072`, `slowpath.rs:1622-1653`), post-write
  authority is deliberately ignored (`:1073-1101`), and a successful write
  length is not proof of downstream routing quiescence. No I/O-release
  witness exists: a `Deferred` ring write is `Terminal`+`Uncertain` while
  its buffer stays kernel-owned (`io_uring_write.rs:855-870`,
  `slowpath_reinject_9506.rs:2184-2197`), and teardown deliberately leaks
  unproven buffers rather than proving release (`io_uring_write.rs:336-351`).
  No `RuleSubscribe` exists: RPDB change detection is sync poll only
  (`ruleListFn`, `routes.go:19,414-418`, fail-closed #3772 M9), and every
  production caller is event-driven (commit/ipmon/route-event paths) —
  no periodic RPDB audit exists, so a quiet-box external rule write has
  an unbounded detection window. No FRR render gate exists (xpfd renders
  `frr.conf` managed sections but owns no zebra hook), and
  `actuateLearnedRouteRefresh` republishes kernel/FRR route events
  WITHOUT `BumpFIBGeneration` behind a 1s/3s coalesce
  (`daemon_route_listener.go:232`, `coalesce.go:41-43`).
- M2: no post-write egress-domain oracle. `delivered` is the
  `xpf_transit_q0_delivered` fence-match witness (`transit_barrier.go:17-22,
  276-280`), not proof of the table selected for q0 egress.
- M3: per-tunnel `ingress_prefixes` membership and all-six-D5c commit
  revalidation are absent outside design text; this is a blocking P2-entry
  gate, not a slice-time follow-up. `ingress_prefixes` has 0 hits repo-wide;
  both tunnel-row types carry exactly 3 fields (`protocol.go:664-668`,
  `snapshot.rs:501-508`), so no transport exists for a frozen prefix set.
  Route-based selector pairs default to `0.0.0.0/0,::/0`, so selectors
  provide zero inner-source admission. No prefix-rotation fence and no
  commit site exist: D14 binds one tick view (`ipsec_inner.rs:232`), so a
  withdrawal between check and write would be invisible by construction.
- M4: shared-device hook/conntrack/RPF/martian/`accept_local` inventory is
  absent outside design text; prove it or refuse the q0 configuration before
  any policy Permit.

New constraints since Sep-20 (compatible, must be respected):

- #10302 fence model (above): permits must reinject via marked `xpf-usp1` q0;
  direct xfrmi plaintext stays fenced. Design D_usp1 choice already assumes this.
- #10638 (`92af5e845`): bind-interface-less VPN hard-rejected at strict commit
  (kills the box-wide quarantine-guard footgun; shrinks unzoned-tunnel doubt arms).
- #10516 (`3eaf618fc`): SA-gated stage-11 passthrough — outer-claim path
  changed; P2 must re-ground outer/inner interaction, not assume Sep-20 shape.
- #10679 (`c55a7f870`): flowless same-family NAT fenced before reinjection —
  touches G3 NAT-order assumptions; re-ground §3 consult table at P2 time.
- `f3c473c02`: IPv6 non-TCP/UDP capture retained (helps P2 v6 parity).

### 4.4 Original-issue symbols (still true, line numbers drifted)

- `SecureTunnel` exclusion class + `matchesSecureTunnelClass`
  (`ingress_exclusions.go:141-192` region) and `userspaceSkipsIngressInterface`
  gate still present; Rust `include_userspace_binding_interface`
  (`planning.rs:433`) still independent. `IsSecureTunnelIfName` still NOT the
  ownership test (predicate note intact).
- `compiler_ipsec_plaintext_warn.go` advisory still renders "NOT evaluated
  against xpf security policies (#5619)" (`:230-234`) — must be removed in the
  same change that makes enforcement real, or it becomes a second untruth.
- Transit-barrier cites inverted by #10302 (see §2): do not quote the issue
  body's `RemoveTransitBarrier` shape as current.

## 5. Design: minimal viable delta

Lane order (F1 done): **P1 → P2 → V1(structural) → P3 → V2**. Each slice is
separately reviewable, fail-closed at every intermediate, with fail-on-revert
cells. The file list is anchored to design §5.2 and re-grounded to master:
all 35 design paths exist, as checked in §4.2.

### P1 — S9.4 session discriminator (pre-req for stateful permits)

- Files: `userspace-dp/src/session/{discriminator.rs,key.rs,lookup.rs,mod.rs}`;
  `userspace-dp/src/afxdp/{flow_cache.rs,session_delta.rs,ha/session_domain.rs,worker/loop_body/mod.rs,cos/flow_hash.rs,icmp_embed/{parse.rs,mod.rs,nat64_match.rs}}`;
  `userspace-dp/src/event_stream/codec/session_sync.rs`;
  Rust interfaces `protocol/{binding.rs,control.rs,security.rs}` and
  `server/{helpers/session_sync.rs,handlers/sync_session.rs}`; Go carriers
  `pkg/dataplane/userspace/{eventstream.go,manager_sessionsync_request.go,protocol.go,protocol_ha.go}`
  and `pkg/daemon/daemon_ha_userspace_convert.go`;
  `pkg/cluster/sync_protocol.go`. `discriminator.rs` owns the u64 tag codec;
  allocate a disjoint IPsec class there; `routing_domain_wire.rs` is a separate
  u32 routing-domain codec and MUST NOT encode the P-MECH discriminator.
  Go/cluster remain opaque carriers. Gate use on explicit peer support for the
  new identity; config-snapshot v35 alone is not an HA session-sync capability.
  Unknown tags remain fail-closed.
- Work: add `Ipsec(if_id)` as a config/tunnel-row-derived identity, never from
  packet contents. Carry it through forward/reverse key transforms, bounded
  cross-discriminator aliasing, import/export, install/delete/expiry,
  worker-local/shared lookup, flow-cache, and HA paths. Native-exact-hit
  precedence is MANDATED as count-before-choosing: when a 5-tuple matches
  both a native exact entry and one or more IPsec aliases, lookup counts
  native and IPsec candidates before choosing and an exact native hit MUST
  NOT hide an ambiguous IPsec alias. Post-count tie-break is AUTHORITY
  SELECTS, never a silent pick: a packet carrying a valid tunnel stamp
  (D14-admitted STN/if_id) selects the matching `Ipsec(if_id)` candidate;
  a packet with native authority (no stamp) selects the native candidate;
  a lookup with absent/invalid authority spanning both identities is an
  ambiguous DROP-and-count (reason byte 62 `AMBIGUOUS_DROP`, new E-row
  39 — allocated in §7), never a guess. Reject-at-install is NOT an
  allowed branch: same-tuple native/IPsec overlap is legitimate
  coexistence (see Acceptance below), and refusing it at install would
  drop valid VPN or native traffic whenever tuples overlap. Scope: the
  count + authority-select rule applies at EVERY exact-key lookup site —
  `session/lookup.rs` (`lookup` `:133`, `lookup_with_origin` `:184`,
  `lookup_with_origin_deferring_close` `:207`, `probe_with_origin` `:149`,
  `probe_with_origin_at` `:166`, `has_session_hit_at` `:108`, shared core
  `probe_record_with_origin` `:94`, alias walk
  `resolve_reverse_translated_handle` `:815`), `flow_cache.rs`
  lookup/insert, `shared_ops.rs` shared + forward-NAT lookups,
  `poll_descriptor` session authority/filter, `session_glue`,
  `icmp_embed` session/quote match, policy rebind, and HA import — plus
  CoS mixing and DELETE under-match (never wildcard; broad purge stays
  GRE-only).
  Keep `None` as the native/untagged class and update the enum's
  "everything but GRE" documentation. For an authority-known IPsec tunnel,
  absent or unknown tags MUST NOT downgrade an imported TCP/UDP key to
  native `None`; ordinary untagged native imports remain importable.
- Consumer contract: `worker/loop_body/mod.rs` policy rebind
  (`policy_rebind_discriminator`, `:75-93`) currently accepts a non-`None`
  tag only for protocol 47; extend it to recover IPsec identity only from an
  exact peer/tunnel-generation authority. CoS flow hashing must mix `if_id`;
  IPv4/IPv6 ICMP quoted-key and NAT64 matching must derive the same identity
  from an authoritative unique tunnel, otherwise remain unresolved/
  miss rather than wildcard across `if_id`s. Session open/close codecs,
  session-delta JSON, binary HA, shared/local indices, reverse/NAT transforms,
  expiry, and flow-cache consumers must preserve one identity end to end.
  DELETE handling must never treat absent/unknown IPsec identity as a wildcard
  or purge sibling IPsec aliases; legacy broad purge stays GRE-only.
- Stability gate: P1 is strictly blocking for P2. Before any Permit exists,
  prove xfrmi recreate, `if_id` change, and zone-move fencing with a
  generation-bound STALE→DROP result, including HA unknown-tag refusal. If an
  `if_id` cannot be frozen per generation under a total order, replace it with
  a daemon-minted stable handle; do not fall back to tuple-only identity.
- Acceptance: two `if_id`s with overlapping 5-tuples, both insertion orders,
  count-before-choosing native/IPsec precedence (no reject-at-install);
  reverse unique/ambiguous/native-miss;
  same-tuple different-worker lookup; alias multiplicity/eviction/generation;
  disjoint wire-tag round-trip against GRE/PPTP tags; absent/unknown and
  old/mixed-peer refusal on JSON and binary HA paths; authority-scoped
  policy-rebind; CoS separation; and IPv4/IPv6 ICMP/NAT64 quote resolution (no
  authority/ambiguous `if_id` remains an unresolved miss). Test exact HA
  import/delete and absent-tag under-match (never delete sibling IPsec keys),
  generation retirement, xfrmi recreate/if_id-change/zone-move races.
  Compile-valid behavioral mutant: collapsing IPsec identity to `None` must
  merge sessions and fail.

### P2 — S9.5 FORWARD policy-permit/q0-write join (closes the original defect)

- Files: `pkg/nfqueue/pipeline.go` and its fragment/permit regression
  contract in `pipeline_9506_test.go`; `pkg/nfqueue/nfqueue.go` (per-packet
  verdict partials); `pkg/nfqueue/reinject_socket.go`; Rust
  `afxdp/ipsec_inner_queue.rs`, `afxdp/ipsec_inner.rs`, worker context and
  `afxdp/worker/loop_body/mod.rs`; `slowpath.rs` and
  `slowpath_reinject_9506.rs`; `pkg/daemon/ipsec_reinject_supervisor.go`,
  `ipsec_topology_owner_9506.go`, and `ipsec_host_fence_reconcile_9506.go`;
  `pkg/routing/{rules,routes,routing}.go`; `pkg/ipsec/policy.go`; the M3
  prefix control plane — config schema + commit validation
  (`pkg/config/types_security.go`, `pkg/config/schema_security.go`,
  `pkg/config/compiler_ipsec_*.go`), row transport both planes
  (`pkg/dataplane/userspace/protocol.go`,
  `userspace-dp/src/protocol/{snapshot.rs,control.rs}`,
  `userspace-dp/src/server/handlers/snapshot.rs`), the tunnel-row publisher
  (`pkg/daemon/ipsec_capture_wiring_9506.go`,
  `pkg/dataplane/userspace/builder.go`), the D14 every-frame check
  (`afxdp/ipsec_inner.rs`), and the RuntimeView/coordinator install path
  (`afxdp/types/runtime_view.rs`, `afxdp/coordinator/`); API
  metrics/witness and the separate V1/V2 evidence harness. The writer is the
  existing single `tx_delegated` outlet unless its early P2 single-writer/
  limiter proof fails; in that case land the bounded queue split BEFORE
  enabling a policy Permit.
- P2-entry blockers — ALL must PASS before any production policy Permit can
  enqueue a q0 write:
  1. P1 identity, HA, and stale-generation gates above.
  2. M1 exact admitted-RPDB proof or an equally exact mandatory refusal gate
     (defined below), both address families, with a named lifecycle owner that
     stops admission, fences already-authorized q0 work (queued + started +
     unreleased I/O) to an acknowledged Rust close, and enforces immutable
     q0 routing before any rule/route change invalidates the proof. External
     rule writers are outside the trust boundary: any unowned live rule
     voids admission (deny-only), it is never fenced around.
  3. M2 q0 egress-oracle design and packet-correlated proof plan; `delivered`
     alone cannot authorize a Permit. If no oracle can distinguish main-table
     254 egress from other routing domains, remain deny-only/re-plan.
  4. M3 full prefix control plane landed (schema + validation + transport +
     publisher + every-frame check + commit revalidation, defined below),
     with frozen per-tunnel source membership, all-six-identity commit
     revalidation, and the E21 cross-tunnel-source cell below. Until every
     M3 allocation lands, P2 stays deny-only; E21 alone is not M3 proof.
  5. G3 consult-vs-skip order re-derived from both current
     `poll_descriptor/mod.rs` sites (`:3992`, `:7645`), `policy.rs`, NAT,
     fragment, and route code BEFORE the permit arm. SA-gated outer/inner
     interaction (#10516), teardown-from-source, MTU and IPv6-parity cells
     pass here, not after permits in V2.
  6. Refuse P-MECH-eligible fragments before `FragPool`/worker admission in
     both families; test late fragments and generation/name reuse for zero
     q0 writes. KEEP the existing
     `TestCapturePipelineFragmentExpiryRemovesRefreshedPoolSet10862`
     (`pipeline_9506_test.go:481-553`) unchanged: it pins generic
     `PipelineEnforcing` pool-expiry behavior (a late fragment opens a new
     incomplete set), not P-MECH permit eligibility. Add a SEPARATE
     P-MECH-specific test asserting the pre-FragPool/no-q0 refusal on the
     permit path only.
  7. Add generation-bound `PMechFlipAuthorizer` (or an owner-approved
     equivalent activation protocol) to the single shared OPEN predicate at
     `tryOpenIpsecPermitAfterFenceAck`/`tryOpenPermit`; recheck peer
     compatibility and failover-refusal state at that writer. A race with
     ordinary host-fence reconciliation, incomplete activation, stale
     generation, or incompatible peer MUST leave OPEN false.
  8. Prove the single-writer `tx_delegated` plus limiter split before the
     Permit arm; if it fails, implement and bound the queue split first.
  9. Parent records owner sign-off that stateful INPUT is OUT of #9506 closure
     scope; without that explicit sign-off, P2 cannot be called issue-closing.
- Ownership/state-publication contract: current `IpsecInnerVerdict` carries
  only request/decision data and `drain_verdicts_into` releases slab/flow/
  tombstone ownership before exposing it. P2 must replace that safe-for-deny
  boundary with a Permit-owned payload or immutable slab handle plus an
  owner-held provisional session/NAT transaction (actual resources/references
  and undo data, not only a phase enum). The sole state owner performs
  `CommitProvisional` or `RollbackProvisional`; transition is monotonic and
  compare-by-expected-phase, never an owner-matching phase overwrite.
  Required phases: `Queued → Adjudicated → Prepared → WriteSubmitted →
  Written | Refused | Uncertain → Finalized`. The writer returns exactly one
  terminal result to the owner. Provisional state is not visible as an
  established session: related reverse lookups during preparation fail closed;
  on `Written`, owner commit/publication precedes release to ordinary lookups.
  `Refused` means proven no write and rolls back once. `Uncertain` is possibly
  emitted: no retry and no rollback; retain a committed-but-inaccessible
  record (defined below), deny reuse/related lookup until reaper retirement,
  and release bytes only after `IoRelease` proves the writer relinquished
  its reference (b). `Terminal`+acked completion alone NEVER proves it.
- Recovery table (authoritative — P2 codes to this table, not around it):
  (a) Dead-owner authority transfer: the finalizer is the S7 reaper acting
  through the existing `retire_worker`/`join_worker_after_termination` path
  (`ipsec_inner_queue.rs:1386-1455`), bound to `WorkerSetAuthority`
  retirement: `retire_worker` reaps ENQUEUED only, and `join` is the
  quiescence witness for worker-owned state. Transfer is a journal CAS on
  `(token, owner_worker, owner_generation → reaper_epoch)`; fix `close`
  (`:796`, currently a bare identity-less remove) to take the finalizer
  identity, and `transition` (`:776-788`) to compare-by-expected-phase with
  no backward jumps. A resurrected worker id can never re-finalize: retired
  generations stay STALE→DROP at admit/drain (`:1190,1223,1265`).
  Live-owner-lost-completion converges here: a live owner whose completion
  is lost (ack-deadline expiry, purge) can NEVER self-finalize to Written
  (no `IoRelease` proof); after the ack deadline it initiates the SAME
  CAS transfer to the reaper, which applies the phase rule below.
  (b) I/O-release witness `IoRelease` (P3O-01: protocol terminality is NOT
  physical finality): a `Terminal` completion plus consumed `drain_ready`
  ack is EXPLICITLY NOT a writer-drop proof — a `Deferred` ring write is
  already `Terminal`+`Uncertain` while its buffer stays kernel-owned
  (`io_uring_write.rs:855-870` deferral,
  `slowpath_reinject_9506.rs:2184-2197` mapping), and ring teardown
  deliberately LEAKS unproven buffers (`mem::forget`,
  `io_uring_write.rs:336-351`), so a closed ring or joined thread proves
  nothing either. The release fact is the TARGET WRITE's terminal CQE via
  `release_matching` on the Deferred id (`io_uring_write.rs:462-471`,
  invariant `:485-499`) OR a terminal `WriteResult` return (`:146-177`).
  Correlation is TYPED internal state, INDEPENDENT of the Go completion
  (the `Uncertain` reason string is debug-only: `decide_resolve`
  `:478-492` discards it and `ReinjectCompletion` `:285-296` carries no
  op id): widen `InFlightWrite{id,bytes}` (`:190-192`) with `ring_id`,
  `request_id`, `permit_epoch`, `journal_token: Option<u64>`; mint
  `ring_id` from a new `NEXT_RING_ID: AtomicU64` in `RingWriter::new`
  (no ring identity exists today); register the obligation row
  `(request_id, journal_token, permit_epoch, ring_id, op_id)` AT the
  `defer` park site (`:855-870`) — only unresolved ops get rows
  (`Done`/`NothingWritten`/`Transferred` hand the buffer back with no
  obligation; the submit→park window owes nothing because no core
  change has happened yet); record release at the `release_matching`
  funnel (`:462-471`, covering `reap_ready`, `reap_matching`, and
  `drain_for_teardown`). The obligation lives in a NEW
  `Arc<Mutex<BTreeMap<(ring_id,op_id), ObligationRow>>>` owned by
  `SlowPathReinjector` (sibling of `reinject_core`, `slowpath.rs:655-658`,
  cloned into the worker like `delegated_core`) — OUTSIDE the core
  entries (destroyed by `ack_ready`, `:1223-1257`), the registry
  (drained by `Drop`), and the writer thread — so it survives core-ack
  + registry-drop + writer exit. The `Drop` handler (`:336-359`) REPORTS
  each survivor as a per-op `Leaked` row there (replacing aggregate-only
  counting for fenced epochs; `RetainedCounters` stays as telemetry).
  Payload reclamation and the M1 Rust ack require `IoRelease.proved`;
  the downstream-skb gate stays INDEPENDENT after I/O finality. LATER
  FIXTURE (four cases): ack `Uncertain`, destroy the core entry, then
  (i) target-CQE release clears the obligation; (ii) failed teardown
  leaves `Leaked` rows → fence ack FAILS; (iii) writer exit leaves rows
  in the reinjector-owned store → fence ack FAILS; (iv) park→resolve
  crash window stays registry+obligation covered.
  (c) ONE coordinated terminal/ownership decision across `ReinjectCore`
  + `ProvisionalJournal` (today disjoint: no `request_id↔token` map, and
  `resolve_write` checks only core state, `:1083-1105`): the S9.5 join
  stores the journal token in the core `Entry` at `register`, binding
  `request_id↔token`; ONE lock order `core.inner → journal.records`
  with `try_lock` on the second and E23/E28-style refusal on contention
  (precedent: `IpsecInnerRouter::admit`); `terminalize` + journal
  `transition` commit atomically under that order; tombstone `ACCOUNTED`
  is the exactly-once linearizer for counters/events; `resolve_write`
  rejects after journal finalization (checks token state too).
  First-terminal-wins holds ACROSS the pair: whichever side wins, every
  late path (second `terminalize`, late `resolve_write`, late owner
  `transition`, verdict replay) sees `Terminal`/`None`/`ACCOUNTED` and
  returns false. Exactly one finalization per token under live-owner,
  lost completion, owner death, writer death, late completion, AND
  restart — no cross-record arbitration gap.
  (d) Per-phase/per-fault table (faults: live-owner OK / lost completion /
  worker death / writer death / restart; `WriteSubmitted` below IS the
  canonical write-start boundary — core `WriteStarted` + journal
  `WriteStarted` unified by (c)):
  `Queued` (core `Queued` + `SLOT_ENQUEUED`): live → normal flow; lost →
  owner/peer cancel → `Refused` path (nothing emitted); death/restart →
  `retire` reaps ENQUEUED (E34), startup sweep, no resurrection.
  `Adjudicated` (NEW persisted: verdict rendered, tombstone `COMPLETED`
  not `ACCOUNTED`): live → register → `Prepared`; lost/death/restart →
  reaper rolls back once → `Refused` → `Finalized` (no write possible).
  `Prepared` (journal `Prepared` + token): live → proceed; lost →
  owner-initiated transfer; death/restart → reaper rolls back EXACTLY
  ONCE (canonical `Prepared→RolledBack`).
  `WriteSubmitted` (coordinated write-start): live → resolve path;
  lost/death/restart → conservatively COMMITTED as `Uncertain`
  committed-but-inaccessible, NEVER rolled back; reclamation needs
  `IoRelease` + fence expiry + deadline (e).
  `Written` (`Terminal` Written + `IoRelease` proved): live → commit +
  publish + `Finalized`; lost → owner reads the coordinated record
  (`Terminal` stands, `Finalized` once); death → reaper completes the
  commit idempotently (`ACCOUNTED`-guarded) → `Finalized`.
  `Refused` (`Terminal` Refused/Fenced/Denied + proven no write):
  rollback once → `Finalized`, identical in all faults.
  `Uncertain` (`Terminal` Uncertain, possibly emitted):
  committed-but-inaccessible in all faults — never rolled back, never
  lookup-visible, never reused — until (e) retires it.
  `Finalized` (NEW: owner-observable terminal + `IoRelease` consumed +
  counters/events emitted exactly once): ABSORBING; every late event
  is rejected.
  (e) Reclaim owner, deadlines, lag bound, ceiling, quarantine (ALL CHOSEN,
  no slice-time invention): owner is a NEW dedicated `d11-reaper` thread,
  period `D11_REAPER_PERIOD_NS = 1_000_000` (1ms, new const) — independent
  of worker poll (covers idle workers) and writer threads (covers dead
  writers) — servicing `drain_timed_out` (`:1476-1512`, wired here; test-only
  today), journal reap, and the obligation-store sweep every tick. Ack
  deadline is `IPSEC_INNER_ACK_DEADLINE_NS = 5_000_000` (5ms, new const,
  matching the Go NFQUEUE `AckDeadline` default, `pipeline.go:181,318`).
  Max sweep lag is `D11_MAX_SWEEP_LAG_NS = 2 × D11_REAPER_PERIOD_NS`
  (2ms), asserted STRUCTURALLY by tick-counted service proof (every record
  serviced at least once per period; bounded drain budgets per tick), never
  by wall-clock flakes. Fence-expiry predicate:
  `fence_expired(gen) := worker_set_retired(gen) AND now - retire_time(gen)
  > IPSEC_INNER_ACK_DEADLINE_NS + D11_MAX_SWEEP_LAG_NS`, with a new
  `retire_time` recorded at `retire_worker`. Quarantine ceiling instantiates
  the EXACT existing constants: `min(STALE_SYNCED_CEILING_MULT ×
  expires_after_ns, STALE_SYNCED_CEILING_ABS_NS)` (mult 3, abs 7d,
  `session/mod.rs:162,171`), measured from a new per-record `first_held_ns`
  with a `ReapStaleSynced`-analogous decision (`expire.rs:674`
  precedent) — PLUS a provisional cap `PROVISIONAL_HOLD_CEILING_NS =
  60_000_000_000` (60s, new const): provisional D11 records never hold
  pinned bytes longer than 60s. Outcomes are SEPARATED: (i) logical
  reservation retirement → tombstone `ACCOUNTED` + counters + `Finalized`
  bookkeeping; (ii) physical buffer → freed/reused iff `IoRelease` proved,
  else deliberately leaked (`mem::forget` + per-op `Leaked` row +
  `RetainedCounters`); (iii) unresolved-I/O obligation → NEVER reaped by
  any ceiling: `Leaked` rows persist in the obligation store (bounded by
  `LEAKED_OBLIGATION_MAX = 16384`, the `terminal_tombstone` precedent)
  and PERMANENTLY fence their epoch (no clean ack for that epoch ever;
  reopen only under a NEW epoch); store overflow sets a poison flag →
  ALL fence acks fail (deny-only) + alarm until operator reset.
  Quarantine is a RESERVED `NatHolder::Quarantine` bit (127; `MAX==128`
  asserts updated) plus a session HOLD-gate extension, INSTALLED AT
  RESERVE — NOT at death/transfer: `ProvisionalJournal::register` plus
  the session_refs/nat_undo reservation sets the quarantine bit/HOLD in
  the SAME critical section (coordinated lock order (c)), so protection
  exists from birth and dead-owner transfer changes ONLY the owner
  identity (worker→reaper). `retire_*`, `release`/`rollback`, lease GC,
  and `expire_*` mask out, skip, or HOLD quarantined resources; the hold
  therefore survives `retire_all_worker_holders` running BEFORE D11
  retire/join (`coordinator/mod.rs:1022-1050`) and ordinary expiry.
  Bound or replace the unbounded per-record `request_ids` vec (`:742`).
  (f) Visibility: per-token phase plus terminal-outcome counters (split
  `ORPHAN_PROVISIONAL` by phase/outcome), journal-depth and
  oldest-uncertain-age gauges, a bounded `uncertain` deque with its own
  counter, an `IoRelease` lag gauge (Terminal→proved), and
  quarantine-held/reaped stats (all absent today). No silent uncertain
  accumulation. (g) Process restart is total owner death: no
  `(worker,generation,token)` authority may resurrect (owner-epoch
  monotonicity; tombstones cleared on run change, announce baseline
  reset); a startup sweep reclaims provisional resources, and HA import
  is the only post-restart state source. Canonical mapping: ADOPT
  `ebcec7ad4:pmech-design.md:766-790` + `queue.rs:1460-1462`
  (`Prepared→RolledBack` exactly once; `WriteStarted`/`Committed`
  conservatively committed, NEVER blindly rolled back) with
  `WriteSubmitted` mapped to the write-start boundary,
  `Written→Committed`-published, `Refused→RolledBack`,
  `Uncertain→Committed`-inaccessible; SUPERSEDE its visibility silence
  with (d)+(e)+(f) above and its uncoordinated terminality with (c).
- Exactly-one-path contract: policy Permit is NOT `nfqueue.VerdictAccept`.
  A permitted frame has one successful q0 write and the original held NFQUEUE
  skb terminally DROPs; never pair `VerdictBatch(ACCEPT)` with q0 for the same
  frame. A partial NFQUEUE batch must reconcile each disposed prefix packet
  and every uncertain suffix packet by identity; no retry-forward. Bound or
  remove worker-verdict requeue so terminal results are idempotent and cannot
  be replayed as a second write. Definitive refusal rolls back once; timeout,
  write-started error, lost completion, or partial-batch ambiguity is
  possibly-emitted/no-retry/no-rollback and still cannot NF_ACCEPT the original.
- Acceptance: the issue bar — denied AND permitted IPv4/IPv6 decrypted-ingress
  with policy/session/counter evidence; packet-correlated one-q0-write plus
  original-DROP proof; HA, MTU, M3, fragments, and teardown cells; pricing gate
  (same-thread ~111ns or measured batched B>=3); M1–M4 gates; and deterministic
  ownership checks for deny, pre-write refusal, successful write, write-started
  uncertainty, lost/duplicate/late completion, and worker death in every phase.

### P2-entry M1–M4 safety gates (all PASS before a production Permit)

- M1 admitted-RPDB predicate: enumerate the live rule set for IPv4 AND IPv6 and
  evaluate the actual q0 packet selectors/actions/order against D_usp1 =
  kernel main table 254. Include destination-only rib-group rules
  (`pkg/routing/rules.go:64-70,675-678`), ingress-scoped next-table rules
  (`:327-333`), PBR/FBF selectors (`:937-948`), probe and mark rules, and any
  other installed selector/action that can change the lookup. A PBR/FBF-only
  refusal is invalid: a PBR-free rib-group rule can still leak q0, while
  unrelated ingress-scoped PBR need not. Distinguish
  `expected_routing_domain=0` from kernel `expected_fib_table=254`; the
  current descriptor fields are initialized to 0 and have no production
  readers (`slowpath.rs:781-782`, `ipsec_inner_queue.rs:162-164`).
  Admission is permitted only for a proved matching predicate; a mismatch
  means deny-only. Fixtures: a no-PBR/FBF rib-group leak refuses;
  ingress-scoped PBR on an unrelated interface does not.
- M1 trust boundary (ENFORCEABLE sole-writer contract, not a declaration):
  (1) Full in-process writer enumeration, `Clear`/`Reassert` included:
  `routing.Manager` facade — `CreateVRF`/`ReconcileVRFs`/
  `ReassertVRFMissTerminator`/`BindInterfaceToVRF`, `Apply`/`Clear` tunnels,
  xfrmi, bonds, reth (no-op apply), probe pins; `ApplyNextTableRules`/
  `ApplyRibGroupRules`/`ApplyPBRRules`; bands next-table window, rib-group
  30000-30999 + return 1500 + clear windows, PBR 31000-31999, VRF
  terminator 2000, L3MDEV 1000; daemon-direct `daemon_flow.go:523`
  mgmt-999 `RouteReplace` + `:707` `RouteDel`, and the
  `daemon_apply_routing.go` commit tail + republish/`BumpFIBGeneration`.
  (2) Kernel-default inventory per admitted OS image: priorities
  0/32766/32767 + l3mdev 1000 with exact match shapes (in-process code
  NEVER writes 0/32766/32767; `bake.py` bakes no routes/rules; networkd
  renders no `[Route]`/`[RoutingPolicyRule]`; `pbr_applied` + fibimport
  exclusions pin the known set). (3) Owned-vs-unowned MATCHING
  ALGORITHM: every xpfd install records `(band, priority, full
  selector, table, owner)` in the install inventory; a live rule is
  OWNED iff it tuple-matches an inventory entry exactly, else UNOWNED.
  (4) Detection + LATENCY BOUND: SYNC `ruleListFn` poll both families at
  every publish (`routes.go:19,414-418`, fail-closed #3772 M9) plus the
  commit-tail reconcile — AND a PERIODIC RPDB AUDIT closing the quiet-box
  gap (every `ruleListFn` caller today is event-driven): owner is
  `(*Manager).statusLoop` at `statusLoopInterval` = 1s
  (`process_status.go:289-291`, always-on while the helper lives, already
  the retry-debt consumer); each tick runs `ruleListFn` both families +
  inventory tuple-match + SYNCHRONOUS `revokeTransitPermitNonblocking`
  on any mismatch, in-tick. Detection-to-deny ≤ 1s + poll + revoke,
  asserted by inject-unowned-rule and audit-liveness cells. The async
  `routeListener` (1s/3s coalesce) is FIB-convergence ONLY, never the
  RPDB safety detector — no `RuleSubscribe` exists (RPDB is poll-only),
  so safety rests on refusal-enforcement + sync poll + periodic audit,
  not async detection. (5) FRR/zebra KERNEL-FIB AUTHORITY (pre-install,
  not ingestion-refusal — refusing the import or bumping a generation
  AFTER install cannot un-install a kernel route receiving q0): xpfd
  owns no zebra hook, so authority is PREVENTION AT CONFIG ADMISSION:
  (i) a NEW table-allowlist render gate in `buildManagedSection`/
  `ApplyFull` REFUSES any FRR config covering admitted q0-path tables;
  (ii) xpfd-owned DENY route-maps for q0-path tables (`policy_render.go`)
  applied to ALL zebra protocols constrain runtime-learned (BGP/OSPF)
  installs; (iii) deployments where zebra is NOT xpfd-config-managed
  are REFUSED admission (same doctrine as RPDB). Defense in depth:
  q0-path-table route EVENTS drive SYNCHRONOUS S4 revoke +
  `BumpFIBGeneration` in the subscribe callback (new caller, BEFORE the
  coalescer — detection latency is callback latency, not 1s/3s), and
  the (4) audit catches the rest; any q0-path kernel route outside the
  inventory → revoke + deny until re-admission. Bounded residual: the
  in-flight set at detection completes under the new kernel env
  (quantified by the in-flight cap, asserted by cell); prevention (i)–
  (iii) is the authority, sync detect+fence bounds the drift.
  Networkd/DHCP/HA-4242/kernel-autoconf/operator writes that appear as
  unowned live rules VOID admission → deny-only until a fresh predicate
  PASS. A watcher is a deny TRIGGER, never a safety gate; unowned rules
  are never fenced around. (6) REFUSED RULE SET, SEMANTIC (literals are
  fast-path only): a rule INTERSECTS q0 iff its selector is not provably
  disjoint from q0 traffic; disjoint requires iif-pinned-to-non-q0 OR
  mark-disjoint (mask pins bits q0 never sets); DEFAULT IS INTERSECT.
  This EXPLICITLY includes the destination-only rib-group leak rule
  (Dst/Table/Priority/Family only, NO Iif/mark — `rules.go:674-684`),
  which matches by Dst alone. Refused while OPEN: any intersecting rule
  add/del, any FIB change to admitted q0-path tables, any usp0/usp1
  receive-mode change.
- M1 mutation linearization (owned end-to-end by the S4
  `ipsecSupervisor`): (1) STOP ADMISSION: `revokeTransitPermitNonblocking`
  → CLOSING + `permitEpoch`++ (`ipsec_reinject_supervisor.go:260-302`)
  PLUS a `FenceAuthorityClose{run_id, generation, permit_epoch,
  fence_seq}` request on the submit socket: `MSG_FENCE_CLOSE = 4`
  (1,2,3,11,12 taken, `slowpath_reinject_9506.rs:36-40`). THE
  NO-NEW-PROCEED BOUNDARY IS THE ACKNOWLEDGED RUST CLOSE, not the Go
  CAS: Rust authorizes from its separately-published `AuthorityState`
  (`:445-473`, updated on `Announce`, `:688-723`), so work authorized
  between Go revoke and Rust close is INCLUDED in the drain (counted
  fenced/cancelled/resolved in the ack). (2) FENCE/CANCEL QUEUED:
  `CancelReinject` + authority-close `Announce`; queued entries
  terminalize `Fenced` via `pre_write` without TUN touch (`:1066-1069`).
  (3) ACCOUNT STARTED WRITES: every `WriteStarted` reaches `Terminal`
  via `resolve_write` (`:1079-1101`) or cancel-then-resolve. (4) RUST ACK
  `FenceAuthorityAck{same tuple, queued_fenced, started_resolved,
  residual_old_epoch, io_unreleased}`: attests NO `Queued`/`WriteStarted`
  AND NO unreleased I/O (`IoRelease`) under the old epoch, computed
  under the SAME core `inner` lock as `pre_write` (`:1041-1072`) and
  `announce` (`:688-723`) — no new lock. TWO-PHASE: scan → resolve
  Proceed-before-scan entries → rescan → ack (a `Proceed` winning the
  race before the scan must resolve before the ack completes; a
  `Proceed` after sees closed authority and `Fenced`). Purges are
  forbidden in the fence window (they surface no completion) or counted
  in the ack. WIRE (CHOSEN — new response type, not Admit reuse):
  `MSG_FENCE_ACK = 13` reply on the submit socket; Rust `match` arm in
  `serve_submit_conn` (`server/reinject_9506.rs:164`) + new
  `encode_fence_ack` beside `encode_admit`/`encode_complete`
  (`slowpath_reinject_9506.rs:1992/2052`); Go
  `reinjectMsgFenceClose = 4` / `reinjectMsgFenceAck = 13` consts
  (`reinject_socket.go:17-21` block), `roundTripLocked` accepted-set
  extension at `:235` (Admit OR FenceAck), new `decodeFenceAck` beside
  `decodeAdmissions`/`decodeCompletions` (`:440/:481`). (5)
  KERNEL-EFFECTIVE STRATEGY: IMMUTABLE Q0 ROUTING + ENFORCED RECEIVE
  MODE — SELECTED, no alternatives. INVARIANT (effective from the first
  old-epoch submission through the LAST possible old-epoch routing
  decision, INCLUDING the CLOSED interval): every old-epoch skb's
  routing decision completes BEFORE its write's I/O finality (enforced
  mode below); step-6 mutation requires ALL old-epoch I/O final
  (`IoRelease`-proved drain + `FenceAuthorityAck` with `io_unreleased==0`
  and `residual_old_epoch==0`); therefore NO old skb can observe the
  post-mutation environment. The CLOSED interval is covered because the
  invariant binds I/O finality (which precedes mutation), not OPEN
  state. ENFORCED RECEIVE MODE on usp0/usp1 (new enforcement): no
  `IFF_NAPI` (already true); RPS cpus EMPTY on all q0 queues; GRO OFF;
  NO XDP program attached; TC classifier pinned (existing mark); kernel
  version PINNED to an allowlist with reviewed tun.c/RPS/GRO semantics
  (extends the V1/V2 kernel identity). SOURCE-BACKED SEMANTICS
  (documented at each pinned kernel): `tun_get_user → netif_receive_skb
  →` (RPS empty → inline, no backlog) `→ ip_rcv → ip_forward` route
  lookup completes synchronously within the `write()` syscall, so
  target-CQE/write-return proves the routing decision already happened
  under the then-current env. ENFORCEMENT: admission verifies /sys
  `rps_cpus` + ethtool GRO + XDP attachment + kernel version; the (4)
  periodic audit re-verifies every tick (mode drift → synchronous
  revoke); change attempts while OPEN are refused; a kernel change
  means deny until the new kernel's tun.c/net-core semantics are
  reviewed. While permits are OPEN the refused-change set is (6): any
  intersecting RPDB rule add/del, any FIB change to admitted q0-path
  tables, any usp0/usp1 receive-mode change. Enforcement points:
  ruleOps choke + facade refuse + apply-boundary refuse + FIB-ingest
  refuse (PBR-skip/table-allowlist extension) + receive-mode refuse
  (`tuneInterfaceBuffers` name-guarded off usp*). Failure behavior: a
  conflicting change is REFUSED with an error; to change it, close
  permits via this full linearization first. Reopen is authorized ONLY
  by fresh predicate PASS + mode re-verified + new
  `AuthorityAnnouncement` (run/generation/epoch) + `allows()` +
  worker-set barrier + ledger finality. NEVER counts as downstream
  quiescence: TUN return length, consumed completion, closed ring, or
  `delivered` counters. (RPS-on-q0 was NOT FOUND today —
  `compiler.go:1840-1857` tunes XDP physical NICs only — v5 ADDS the
  enforcement rather than depending on current state.) (6) MUTATE under
  the single writer, re-snapshot the live rules, re-evaluate the
  predicate, reopen only on PASS. CHECKS (benign, all required): FIRST
  CHECK — writer paused after `pre_write_check` but before the TUN call
  → mutation MUST NOT become effective; DEFERRED-I/O CHECK — op held
  unresolved in the ring after terminal-`Uncertain` is acked → the M1
  ack MUST fail; DOWNSTREAM-LIFETIME CHECK — mode cells
  (RPS-empty/GRO-off/no-XDP/kernel-pinned enforced + drift→revoke)
  PLUS mutation attempted with unreleased I/O → prohibited (a
  terminal-CQE-complete skb pending downstream is IMPOSSIBLE under the
  enforced mode because its routing already decided — asserted by mode
  proof, not counters).
- M2 egress oracle: before the first Permit is coded, approve a design that
  correlates each q0 submission to the actual selected egress table/domain and
  observes post-write disposition. The nft `delivered` witness is only a
  fence-mark match (`transit_barrier.go:17-22,276-280`), never this oracle.
  If table-254 egress cannot be distinguished from other routing domains, keep
  every production policy result advisory/deny-only and re-plan.
- M3 overlap/source admission — FULL LANDING PATH (no slice-time invention):
  selectors for route-based VPNs default to `0.0.0.0/0,::/0`
  (`pkg/ipsec/policy.go:593-600,672-675`) and give ZERO inner source
  admission, so the frozen prefix set carries the entire check. (1) SCHEMA:
  new per-tunnel `ingress_prefixes` on `IPsecVPN`
  (`pkg/config/types_security.go:1969`, beside `BindInterface`/`LocalID`/
  `RemoteID`) plus schema leaf (`pkg/config/schema_security.go`); non-empty
  is MANDATORY for every P-MECH-admitted tunnel — a tunnel with no frozen
  prefixes is not admitted, never "open". (2) VALIDATION/PROVENANCE: commit
  validator alongside `compiler_ipsec_bindiface.go`,
  `compiler_ipsec_trafficselector.go`, and the #9624 SA-collision gate:
  CIDR-parsed, normalized, overlap-REJECTED across admitted tunnels
  (overlapping sets across two tunnels refuse at commit — E21 is the
  runtime backstop, not the overlap manager); provenance is AUTHORED
  config, never derived from traffic selectors. Strict-vs-lenient is
  FIXED on all three paths (NOT the #9624 warn-and-keep precedent):
  strict commit ERRORS on overlap/empty via `CompileConfig`
  (`compiler.go:42`) / `compileTreeStrict` (`configstore/store.go:616`);
  tolerant load AND HA/peer-sync run the SAME prefix validator in the
  lenient leg — `handleConfigSyncWithAncestry`
  (`daemon_ha_sync.go:735`) → `syncAndApply`
  (`daemon_apply_commit.go:482/490`) → `Store.SyncApply`
  (`configstore/store.go:954`) → `compileTreeLenient` (`:819`; new
  validator call site, named here), boot twin `Store.Load`
  (`store_persist.go:79`) — with omit-row quarantine-to-deny on
  violation (never warn-and-admit; quarantine mechanism precedent:
  `quarantineCollidingZones`, `zones_quarantine.go:57`). Per-tunnel
  deny mechanism is OMIT-ROW: a withdrawn tunnel's row is absent from
  the new generation, so D14 exact-STN match misses → deny;
  present-with-empty-list is INVALID (validator + serde reject, never
  membership-open). (3) TRANSPORT: extend `IpsecTunnelRowSnapshot` BOTH
  planes (`protocol.go:664-668`, `snapshot.rs:501-508`) with the frozen
  set as SPLIT v4/v6 SORTED NORMALIZED CIDR vecs (`AddressBook`
  `PrefixesV4`/`PrefixesV6`, `protocol.go:917`, precedent; WG
  `AllowedIPs`, `snapshot.rs:1016`, matching precedent);
  `MAX_INGRESS_PREFIXES_PER_TUNNEL = 64` per family vec (CHOSEN: 8× the
  WG data-plane bound (8) for multi-homed sites, half the ANNOUNCE
  control-plane bound (128) to keep the per-frame D14 linear scan
  cheap); serde REQUIRED (missing/empty → row invalid → tunnel denied,
  never default-open); each row bound to
  `IpsecTunnelSnapshotGeneration`. VERSION (CHOSEN — bump AND floor
  together, as precedents do, not a disjunction): single v35→v36
  exact-equality bump OWNED BY THE M3 SLICE (`ProtocolVersion`,
  `protocol.go:359`; `CONFIG_SNAPSHOT_PROTOCOL_VERSION`, `control.rs:215`;
  `handlers/snapshot.rs:28-34` gate) PLUS `MinProtocolIngressPrefixes =
  36` floor for cross-chassis shape gating (following the
  `MinProtocolMultiZoneScopedPolicy` pattern); P1 needs NO snapshot
  bump (discriminator rides the length-gated HA-sync wire + the existing
  `IfID` row field). Fixture/contract updates (`protocol_wire_v1.json`,
  `snapshot_shape_version_8892`, `snapshot_epochs_9506`,
  mixed-version matrix).
  (4) PUBLISHER/OWNER + ROTATION FENCE: the existing tunnel-row publisher
  (`ipsec_capture_wiring_9506.go` `tunnelRowsSnapshot`, via `builder.go`
  stamping) creates, rotates, and retires prefix sets on tunnel
  create/update/recreate/zone-move/refresh, tied to
  `IpsecTunnelSnapshotGeneration` + config/FIB generations;
  withdrawn/empty sets DENY (same deliberate deny-only binding as empty
  rows → generation 0 → E28). Prefix create/update/retire runs the SAME
  synchronous 6-step owner protocol as M1 (S4 `ipsecSupervisor` covers
  RPDB AND prefix mutation; the prefix generation joins the fenced epoch
  set; the Rust ack covers no-queued/started-under-old-prefix-generation
  and no unreleased prefix-generation I/O). (5) EVERY-FRAME CHECK:
  membership in `d14_zone_gate` (`afxdp/ipsec_inner.rs:232`), EXTENDED IN
  PLACE (no successor function), before policy evaluation AND before any
  session/NAT state mutation. (6) REVOCATION SEMANTIC (CHOSEN):
  DRAIN-THEN-EFFECTIVE — the M1 shape, not late revocation (no
  post-`WriteStarted` revocation point exists: `Fenced` is `Queued`-only,
  `cancel` cannot terminalize `WriteStarted`, `resolve` ignores
  authority). Withdrawal decision → 6-step fence (stop admission under
  the old prefix gen, cancel queued, drain started + `IoRelease`,
  `FenceAuthorityAck`) → publish the new view → revocation EFFECTIVE.
  In-flight old-authorized writes complete under still-effective
  authorization (bounded: in-flight cap +
  `IPSEC_INNER_ACK_DEADLINE_NS` + writer liveness; deadline expiry with
  an unresponsive writer → permits stay CLOSED deny-all + alarm until
  resolve/death — never silent effectiveness). SECURITY PROPERTY: NO
  emission under an EFFECTIVE-revoked prefix. SERIALIZATION is the
  acknowledged-close RENDEZVOUS (not a shared mutex — coordinator
  publish is lock-free Arc-swap, core `inner` a different domain):
  publish MUST obtain `FenceAuthorityAck` (old prefix gen) BEFORE the
  Arc-swap install; the ack scan under core `inner` linearizes against
  `pre_write`/`resolve_write`/`terminalize`; the writer holds old-gen
  `WriteStarted` across revalidate→TUN→resolve, so it is visible to
  the scan and BLOCKS the ack (two-phase rescan closes the
  pre_write-after-scan race). `revalidate_permit_commit(stamped,
  current)` (called from `slow_path_worker` after `pre_write` `Proceed`,
  before the TUN write; `stamped` = frame's generations + prefix-hash +
  zone/policy hash; `current` = CURRENT installed RuntimeView at commit,
  `ha.runtime.load`/`load_full`, never the tick view; ANY mismatch →
  `Refused`/`Stale`, NO TUN touch) catches rotations that completed
  BEFORE `pre_write`; rotations attempted DURING revalidate→TUN block
  on the fence. All six D5c identities revalidate here: D_usp1/main-254
  route-domain, FIB generation, inventory generation, tunnel/if_id plus
  prefix membership, zone/policy hash, RuntimeView generation.
  (7) CELLS: E21 (`DOMAIN_OVERLAP`, reason 45 / erow 21, `pipeline.go:1527`,
  `ipsec_inner_queue.rs:68,112`) disjoint-A/B cell — A-stamped frame with
  B-only inner source → E21 DROP-and-count, no shared-q0 fallback — PLUS
  commit-time overlap-reject, prefix-refresh rotation, row-retirement-deny,
  lenient/HA overlap+empty-deny, and drain-then-effective withdrawal
  cells: (i) pause the writer after final revalidate (`WriteStarted`),
  attempt withdrawal → withdrawal BLOCKS (not effective); resume → write
  completes under still-effective old gen; fence drains; withdrawal
  effective; subsequent frames denied; (ii) publish attempt between
  revalidate load and TUN entry → BLOCKS; assert no q0 under an
  effective-revoked prefix + blocked publish; (iii) withdrawal with no
  in-flight → effective immediately; (iv) deadline expiry with a stuck
  writer → permits CLOSED + alarm, no silent effectiveness. Until
  (1)–(6) ALL land, P2 stays deny-only.
- M4 shared-device inventory: prove hook/conntrack/RPF/martian/`accept_local`
  behavior for the q0 shared device and both families before permitting; any
  owner-unknown or unbounded shared state refuses the configuration.

### P3 — D12a Option A stateless INPUT (conditional, after P2)

- Files: `pipeline.go` (admit inet input), `slowpath_reinject_9506.rs` (INPUT
  terminal path), supervisor `InputPermitCommitter` (new), fence interplay.
- Gate: ONLY after D12a-C1 (ICMP/ICMPv6 skip-install + reply deliverability)
  AND D12a-C2 (T5 host-bound disposition, both verdicts) pass; ICMP/ICMPv6/
  flowless only; every stateful INPUT miss stays E37/`ReasonInputBoundary=59`
  DROP. Option B remains deferred/unauthorized — no accept-without-session
  fallback, ever.

### V1/V2 — VOID→PASS flips

- V1 structural (no permit dependency): counters DONE (`1838aaf59` + Go
  decode + Prometheus — verify in-flip); remaining are harness-owned exact
  observers (dynamic fence-set, per-rule provenance/PF-bind,
  same-priority-chain absence, VRF transition, workload latency;
  `test/incus/*`, zero product overlap). Before any live verdict, require
  source-bound manifests and running-process hashes for BOTH `xpfd` and
  `userspace-dp` on BOTH firewalls, plus the relevant kernel/classifier
  identity. T12 structural cells flip VOID→MATCH with archive-verbatim
  ATTEST/RESTORE/SUMMARY; G2 consumer cells remain VOID until P2 gates pass.
- V2 after entry gates and permit implementation: consumer round with permits
  flowing; packet-correlated one-q0-write/original-DROP proof; per-shape stage
  rates, measured B>=3 economics, memory accounting
  (skbs→verdict queues→TUN), and throughput/fairness. Teardown-from-source,
  SA-gated outer/inner, fragment, MTU, and IPv6 parity are P2-entry gates, not
  V2 afterthoughts.

### Scope cuts (explicit)

- Single-writer `tx_delegated` + `RateLimiter` split is proven BEFORE the
  permit arm; if it fails, land a bounded queue split before P2 can pass its
  entry gate. It is not a post-failure fallback.
- `logical_ingress.rs` and `policy.rs`: reuse the canonical ingress builder
  and existing evaluator, but re-derive the G3 stage/call-site order first.
- Product changes remain separate from the evidence harness; harness work is
  required for V1/V2 attestation and packet-correlated proof, not prohibited.

## 6. Risks

- R1 — Sep-24-class rebase collision recurrence: any lane replaying
  `fix/9506-mech` onto master will collide. Mitigation: this plan records
  TREE_IDENTICAL; lanes start from `origin/master`, never from the deleted
  branch. Residual: the tip object may eventually GC; the record here + #10483
  is the durable proof.
- R2 — Fence-model misread as "fixed": #10302 drops everything, which can be
  mistaken for enforcement. Mitigation: acceptance requires PERMITTED flows
  with evidence, not just absence of bypass. The advisory text is the tripwire —
  it must be removed only by the enforcing change.
- R3 — G3 order rot: #10679 (NAT fence) and #10516 (SA-gated passthrough)
  postdate the design's consult table. Mitigation: P2 re-grounds §3 against
  master before coding; consult-vs-skip table re-derived, not copied.
- R4 — P1 wire compatibility: the config-snapshot protocol at v35 and the
  length-gated HA session-sync discriminator are separate contracts. P1 must
  define an immutable per-feature floor/peer capability for any required
  snapshot shape, plus absent/unknown-tag import behavior; do not assume a v35
  config bump alone gates the HA tag.
- R5 — M1/M2 kill polarity: no production Permit code until the exact admitted-
  RPDB predicate, the in-flight fence + kernel-effective gate, the trust
  boundary, and the M2 egress-oracle design pass. Any admitted config that
  fails or later invalidates M1 remains fenced/deny-only; absent M2 proof means
  re-plan, not mid-P2 permit testing. See the P2-entry gates.
- R6 — D12a boundary creep: stateful INPUT misses stay E37; before P2 lands,
  the issue owner must record sign-off that stateful INPUT is outside #9506
  closure scope. No sign-off means P2 cannot be declared issue-closing; any
  later Option B claim still needs two-resource prepare/finalize proof.
- R7 — Single-writer/limiter coupling: prove the shared `tx_delegated` outlet
  and limiter split before enabling Permit. If that proof fails, implement the
  bounded queue split and re-run the entry gate; never expose a second writer.
- R8 — Live-proof dependence: P1/P2 entry gates and V1/V2 need the loss cluster
  with XFRM SAs, traffic, source-bound builds, and attested `xpfd` +
  `userspace-dp` processes on both firewalls. Prior rounds burned the
  attestation budget on wrong-binary/fixtures-missing VOIDs. Run structural
  flips first; no fixture-dependent live round may report PASS without complete
  artifact, kernel/classifier, restore, and packet-correlation evidence.
- R9 — Rotation/finality/downstream bypass: an unfenced prefix rotation
  (pass-check → withdraw → still-write-q0), a `Terminal`-as-release
  confusion (reclaim or M1-ack while a `Deferred` op still owns its
  buffer), an old skb routed after step-6 mutation, or a zebra-installed
  q0-path route reopens the exact spoof/misrouting M3/M1 exist to
  prevent. Mitigation: prefix mutation runs the 6-step fence with
  fresh-view `revalidate_permit_commit` (drain-then-effective);
  `IoRelease` (never `Terminal`+ack, closed ring, or `delivered`) gates
  reclamation and the M1 ack; the enforced receive mode proves routing
  precedes I/O finality; the FRR render gate + deny route-maps + sync
  revoke/bump fence zebra. Kill polarity: any lane that cannot prove
  the fence, the release fact, the mode, or the render gate keeps P2
  deny-only.

## 7. Test plan

Per slice (each cell fail-on-revert; RED-on-revert evidence required in the
slice commit's Validation section):

- P1 cells: disjoint IPsec tag round-trip against every existing GRE/PPTP tag;
  Go JSON plus cluster binary open/close preservation; two `if_id`s with
  overlapping 5-tuples in both insertion orders; count-before-choosing
  native/IPsec precedence, reverse unique/ambiguous/native-miss,
  different-worker lookup, and alias multiplicity/eviction/generation;
  authority-scoped policy-rebind and absent/
  unknown/old-peer import refusal for IPsec while preserving untagged native
  imports; absent/unknown DELETE under-matches without deleting sibling IPsec
  keys; CoS separation; IPv4/IPv6 ICMP and NAT64 quote resolution or unresolved
  miss without unique tunnel authority; HA delete/generation retirement; and
  xfrmi recreate/if_id-change/zone-move fencing with STALE→DROP. Revert mutant:
  compile-valid collapse of `Ipsec` to `None` must merge sessions and fail.
- P2-entry cells must PASS before production Permit code: exact admitted-RPDB
  IPv4/IPv6 fixture with PBR-free rib-group leak refusal and unrelated
  ingress-scoped-PBR control; M1 enforcement (ruleOps/facade/apply/FIB/
  receive-mode refusal cells for every q0-intersecting change incl the
  Dst-only rib-group rule; owned-vs-unowned tuple-match cell; per-image
  kernel-default inventory cell; PERIODIC AUDIT cells: inject unowned
  rule → deny within 1s + poll + revoke, plus audit-liveness cell;
  FRR render-gate refusal cell + deny-route-map cell + unmanaged-zebra
  admission-refusal cell; q0-path route-event → synchronous revoke+bump
  cell (callback latency, skipping coalesce) with bounded in-flight
  exposure quantified); M1 in-flight fence sequence (revoke → Rust
  acknowledged close → cancel queued → account started + unreleased I/O
  → `FenceAuthorityAck` → immutable-routing + receive-mode gate →
  mutate → reopen) including the FIRST CHECK (writer paused after
  `pre_write_check`), the DEFERRED-I/O CHECK, and the DOWNSTREAM-LIFETIME
  CHECK (mode enforcement + unreleased-I/O-prohibits-mutation); ack WIRE
  cells (`MSG_FENCE_CLOSE=4`/`MSG_FENCE_ACK=13`, Rust match arm, Go
  accepted-set + `decodeFenceAck`); packet-correlated M2 table-254 egress
  proof; M3 landing (v36 bump + `MinProtocolIngressPrefixes=36` + MAX=64
  + fixtures, commit-time overlap-reject, prefix-refresh rotation,
  row-retirement deny, lenient/HA overlap+empty deny) with rotation fenced
  by the 6-step protocol, fresh-view `revalidate_permit_commit`,
  all-six-D5c revalidation, A-stamped/B-only-source E21 DROP, and the
  drain-then-effective withdrawal cells (blocked-withdrawal,
  interleaving-blocked, immediate-when-idle, stuck-writer-CLOSED+alarm);
  blocker-5 gates as ENTRY cells with the per-gate observables below
  (deny-only); zone-map matrix (zoned/unzoned/ambiguous/
  cross-spelling/duplicate-if_id/stale); Go hook matrix (pass/drop/nil/
  stale/shadow); admit codes (each new code + unknown-code refusal);
  supervisor committer matrix (`Accepted+error`, timeout-uncertainty
  no-retry; retained-handle-only pre-committer is SUPERSEDED by the v5
  recovery table); route-domain identity (exact D_usp1 vs other-domain
  E22); owner sign-off that stateful INPUT is outside closure; host-fence
  reconciliation racing incomplete activation/peer incompatibility leaves
  OPEN false; fragments: generic pool-expiry regression UNCHANGED plus a
  separate P-MECH pre-FragPool/no-q0 refusal test in both families
  (including late fragments) with zero q0.
- Blocker-5 deny-only observables (each: input / fixture / expected
  reason+counter+event / fail-on-revert mutant): G3 order — frames
  exercising BOTH `:3992` (post-NAT tuple+ICMP) and `:7645`
  (reconstructed incl NAT64) plus flowless `l4_present=false` plus
  #10679 NAT-fenced flowless / permit+deny frames per site / consult
  order matches the re-derived table, deny → reason 5/6 + `PolicyDeny`
  event (byte 134) + `V1PermitSuppressed`/`D11Deny52` as appropriate /
  delete-a-site-consult (or tuple flip) must fail the cell. SA-gated
  #10516 — outer ESP with/without SA + inner claim (remote-claim,
  unseeded SPI, AH) / Stage-11 `poll_stages` fixtures / ungated →
  raw-drop + `ipsec_sa` counters + closed ADMIT codes / SA-check
  negation must fail the cell. Teardown-from-source — pending/early/
  duplicate/late completions / completion-ACK reintro + steering
  fixtures / first-wins exactly-once terminal + Late/Uncertain counters
  / second-wins (or Uncertain-rollback) must fail the cell. MTU —
  over-`live_mtu` inner frames + PTB / clamp at `submit_adjudicated` +
  `InterfaceMtu` fixtures / Adjudicated refuse + mtu/dropped counters
  + PTB-filter drops + Reason54/frag counters / guard-removal (or
  order-swap) must fail the cell. IPv6 parity — v6 equivalents of every
  v4 cell (ICMPv6, flowless, NAT64/NPTv6, quote-v6, publish gate, FIB
  anycast) / family matrix / identical reasons/counters per family /
  v6-skip (or publish-widen) must fail the cell.
- P2 ownership/terminal cells assert real session/NAT resources and slab/flow
  ownership at every monotonic phase: deny, pre-write refusal/rollback once,
  Written/commit once, write-started uncertainty/no retry/no rollback, lost or
  duplicate/late completion, and worker death in every phase. Recovery-table
  cells: 8-phase × fault matrix (live / lost-completion / worker death /
  writer death / restart) incl live-owner-lost-completion converging to
  reaper transfer (never self-`Written`); coordinated decision
  (journal-finalized → `resolve_write` rejects; every cross-pair late path
  false); obligation fixture, FOUR cases (ack `Uncertain`, destroy the
  core entry, then target-CQE clears / failed teardown leaves `Leaked` →
  fence ack FAILS / writer exit leaves rows → fence ack FAILS /
  park→resolve window covered); deadlines (`d11-reaper` 1ms owner,
  5ms ack deadline, 2ms max lag by tick-counted service proof,
  STALE_SYNCED ceiling constants + 60s provisional cap, separated
  logical/physical/permanent-fencing outcomes, leak-store poison);
  quarantine PREINSTALL fixture (start with a provisional reservation
  NOT yet uncertain, run `retire_all` before join → SURVIVES; ordinary
  expiry HOLDs; ceiling reap bounded + counted); `Uncertain` is
  committed-but-inaccessible (no lookup visibility, no reuse, no
  rollback); restart resurrects no authority. Exercise partial NFQUEUE
  batches (disposed prefix vs uncertain suffix) without retry-forward;
  bound/remove verdict requeue and prove exactly-one `tx_delegated`
  writer + limiter behavior before a Permit arm.
- E-row taxonomy cells: the closed table is `reason_for_erow` (E1–37 →
  reason byte, `ipsec_inner_queue.rs:94-129`), validity {5,6}∪[32,60]
  (`:88-90`, `reason_map_is_closed` test), Go mirror
  (`pipeline.go:1511-1543`). Fault-injection for EVERY touched E-row
  asserting counter + event exactly once with no unmapped terminal.
  BYTE ALLOCATION (CHOSEN — the set is fully assigned, so validity
  extends to {5,6}∪[32,62]): 61 `FENCED` (new E-row 38 → 61; SPLITS
  `Fenced` from `Stale`: new `PipelineStats.Fenced` +
  `xpf_ipsec_capture_fenced_total`, `OUTCOME_FENCED=6` + `fenced` label
  already exist; move `pipeline_9506_test.go:607` expectation);
  62 `AMBIGUOUS_DROP` (tie-break ambiguous-DROP; new E-row 39 → 62).
  `Written` needs NO deny byte (success terminal: `completed_written`
  counter + ledger `Written` terminal + D11 event — named, not
  byte-mapped); `Refused` needs NO single byte (each refusal carries
  its specific deny reason); `Uncertain` keeps 48, E21 keeps 45.
  DECODER/FIXTURE UPDATES (all REQUIRED): `is_valid_reason_byte`,
  Go `Valid()`, `String()` arms, `reason_for_erow` arms,
  `reason_map_is_closed` update, NEW Go exhaustiveness test (no Go
  closed-range test exists today), spot pins. New/changed mappings
  (all REQUIRED): E38/`Fenced`, E39/`AMBIGUOUS_DROP`,
  `Cancelled`→`stats.Cancelled`+`xpf_ipsec_capture_cancelled_total`+ledger,
  recovery-visibility (ORPHAN split by phase/outcome, journal-depth,
  oldest-uncertain-age, uncertain-deque, `IoRelease`-lag,
  quarantine-held/reaped). Injection harness: Rust fixtures
  (`ipsec_inner_queue` tests `:1504`+, adjudication fixtures,
  coordinator stale rows) + Go `pipelineTestSubmitter`/socket scripts
  (admit codes incl `NoGeneration`/`TunnelRowMissing`/99, outcomes
  1–10) + ledger cells. Exactly-once mechanism: `RequestTombstone`
  PENDING→COMPLETED→ACCOUNTED CAS + `claim_stale`, core
  `terminal_tombstones` (cap 16384 + overflow poison), ledger
  first-terminal-wins (+`Duplicate`/`LateAttempts`). V1-unmapped
  emitters (E2/7/9/10/11–15/16–18/19/20/22/26/27/29/30/35/37) stay
  unmapped until their slice lands; any P2-touched row without a
  row+counter+event mapping fails the gate.
- Compile-valid semantic mutants each fail a named behavioral check:
  collapse IPsec identity to None; bypass policy deny; remove q0 enqueue;
  change original DROP to NF_ACCEPT; duplicate q0 submit; omit refusal rollback;
  roll back after uncertain emission. Build failure, missing test, or wrong
  artifact is VOID, never a behavioral RED or PASS.
- P2 live: packet-correlated one q0 write plus original DROP, denied and
  permitted v4/v6 with policy/session/counter evidence; HA failover, MTU and
  teardown-from-source (permit-flowing counterparts of the entry cells
  above); measure stage rates, throughput/fairness, memory, and
  same-thread ~111ns or actual batched B>=3 economics.
- P3 cells: D12a-C1/C2 proof cells (must PASS before any INPUT permit ships);
  stateless-shape matrix; stateful-miss E37/E59 DROP matrix.
- V1/V2: T12/G2 rounds per `docs/log/9506-observe.md` — archive-verbatim
  ATTEST/RESTORE/SUMMARY, restore/residue clean, and source-bound manifests +
  running-process hashes for BOTH `xpfd` and `userspace-dp` on BOTH firewalls,
  plus kernel/classifier identity. Mismatched/stale-helper negative must fail
  attestation; `delivered>0` alone never passes.
- Scoped commands (examples; lane re-grounds at slice time):
  `go test ./pkg/nfqueue/ -run 'TestCapture|TestPipeline|TestD11' -count=1`,
  `go test ./pkg/daemon/ -run 'TestIpsec|TestPMech|TestFence' -count=1`,
  `cargo test -p userspace-dp session::`,
  `cargo test -p userspace-dp slowpath_reinject_9506`.
  No project-wide suites mid-flight (parent owns validation).

## 8. Open questions (kill-inviting; each states its kill polarity)

1. **Is the fail-closed fence now the enforcement, making P-MECH permits a
   feature rather than a security fix?** If the owner accepts "VPN transit
   drops by default" as the shipped posture, P2 loses its security urgency and
   this plan's sequencing (P2 before V1-structural) is wrong — but the
   advisory's "NOT evaluated" text and the issue's permitted-flow acceptance
   would both need rewriting first. KILL POLARITY: a YES with owner sign-off
   kills P2-as-security-fix (re-file as feature, close #9506 on fence-only).
   Assessment: NO — the advisory + acceptance are unchanged, and an
   always-drop VPN is not a shipped VPN.
2. **Does any live path still forward unadjudicated xfrmi plaintext around the
   fence (bridge leg, loopback exemption, pre-first-install window)?** The
   bridge-family-unsupported degradation (`IsTransitBarrierBridgeUnsupportedOnly`),
   the `fec7d18a3` loopback exemption, and boot/pre-install transitions are
   the three places a residual bypass would hide. KILL POLARITY: a confirmed bypass
   does not kill the plan but kills its "fail-closed at every intermediate"
   claim — F1-style hardening must precede P1. Assessment: unknown until a
   bypass-hunt cell covers all three; scheduled as P1-entry work.
3. **Can M1 admit a precisely inventoried RPDB state, fence in-flight q0
   work across mutation, hold old skbs' routing environment through the
   CLOSED interval, AUTHORIZE the kernel-FIB writer set, and can M2 prove
   actual q0 egress domain before emission?** A PBR/FBF-only refusal is
   disproven as a complete fallback: a Dst-only rib-group rule may still
   steer q0, while unrelated ingress-scoped PBR need not. KILL POLARITY:
   if the admitted-RPDB predicate cannot be enforced within the sole-writer
   trust boundary, the in-flight fence + receive-mode downstream invariant
   cannot be proved, FRR/zebra q0-path installs cannot be prevented at
   render time, or M2 cannot distinguish table 254, all policy Permits
   remain deny-only and K2 re-plan triggers. Assessment: all are blocking
   P2-entry gates; no permit implementation is authorized until they pass.
4. **Is the D11 attestation path close enough to a production permit that P2
   should extend it rather than build the §2.5 committer?** The attestation arm
   already proves a bounded transport/verdict/reinject join with
   provenance/zone/lease checks. KILL POLARITY: if reviewers show the attestation
   join subsumes the production join, the §2.5 supervisor-committer design is
   overbuilt — kill that section, re-plan P2 as attestation-generalization.
   Assessment: NO — attestation is selector-armed, single-shot, witness-shaped;
   production needs generation-fenced multi-flow commit/rollback. But the
   question must be put to hostile review at P2 slice time.
5. **Does the `Pptp(handle)` discriminator precedent actually transfer to
   `Ipsec(if_id)`, or does `if_id` have direction-varying or mutable semantics
   that break it?** `if_id` is config/kernel-derived, not packet-derived, which
   is encouraging — but xfrmi recreate/`if_id` change/zone-move races (§5.5
   fencing) are exactly where a handle's stability assumptions die. KILL
   POLARITY: if `if_id` cannot be frozen per-generation with a total order on
   recreate, P1's identity axis is unsound — kill P1-as-designed, re-plan on a
   daemon-minted stable handle. Assessment: design's generation fence (D13/D14
   STALE→DROP) answers it on paper; needs the recreate/zone-move race cells to
   hold on master.
6. **Is same-thread adjudication still reachable, or has the D11 worker-transport
   shape locked P2 into the cross-thread handoff that B2 priced at 226–452% of
   budget?** The D11 bridge admits frames to worker transport; if P2's verdict
   path inherits per-packet cross-thread sync, the pricing gate fails by
   construction and only B>=3 batching (or a same-thread redesign) survives.
   KILL POLARITY: if neither shape fits on loss-cluster numbers, P2 cannot ship
   as a dataplane path — kill the bridge-topology, re-plan. Assessment: unknown
   until V2 measures; the design's batched-handoff provisions are the hedge.
7. **Who owns the VRF story — is `D_usp1 = main-table-254, non-VRF` still the
   owner-authorized choice after #10679/#10516?** Later work touched NAT fencing
   and SA-gated passthrough in ways that interact with route-domain identity.
   KILL POLARITY: if the owner now requires multi-VRF P-MECH in V1, the D5c/M3
   single-domain design is insufficient — kill §1.5-as-Y, re-plan item #6.
   Assessment: no evidence of changed ownership; confirm at P2 kickoff.

## 9. Evidence appendix (commands run this assessment; cwd `/var/tmp/worktrees/9506-research`)

```text
git rev-parse --abbrev-ref HEAD                    # research/9506-delta
git status --porcelain=v1                           # clean (pre-doc)
git rev-parse origin/master                         # 028c4e4e22a690fdacc776523767661f665f50c8
git branch -a | grep -i 9506                        # delta/pmech-design/reground/xfrm-capture (local+origin),
                                                    # origin/fix/9506-{f1,sf1-fence-removal,vpn-ingress}; NO fix/9506-mech
git cat-file -t 35a0b7e1a                           # commit (dangling tip object survives branch deletion)
git diff b71c52d60 35a0b7e1a --quiet && echo TREE_IDENTICAL   # TREE_IDENTICAL
git show --stat b71c52d60 | head -8                 # 33 files, 7043 insertions, 360 deletions
git log --oneline b71c52d60..origin/master -- <f>   # per-file churn (§4.1; 0 for xfrmi.go,
                                                    # capture_identity, divert_identity, ipsec_inner_queue.rs,
                                                    # reinject_socket.go)
grep -n 'V1PermitSuppressed\|VerdictAccept\|submitEligible' pkg/nfqueue/pipeline.go
                                                    # enforcing arms all VerdictDrop; Accept only PipelineShadow
grep -rn 'Ipsec(' userspace-dp/src/session/         # no hits → S9.4 absent
grep -rn 'InputPermitCommitter\|CompletionInputReady' pkg/ userspace-dp/src/
                                                    # no hits → D12a absent
grep -rn 'xpf-usp1' pkg/routing/*.go                # no hits → M1 absent
sed -n '405,470p' pkg/daemon/daemon_transit_gate.go # InstallArmedTransitFence (fence inversion)
docs/log/9506-observe.md tail                       # 30/30 VOID (G2 consumer unavailable)
```

Prior-review note: the Sep-25 delta assessment comment (issue #9506) and its
D11-clarification comment were used as the starting inventory and every load-bearing
claim in them was re-verified against `028c4e4e2` above; agreements are cited by
file:line, and the two corrections versus Sep-25 are (a) F1 is now landed
(#11107) and (b) protocol is v35, not v30.
