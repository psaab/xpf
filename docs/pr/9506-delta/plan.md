# 9506 delta plan: ship P-MECH permits on the current master (research/9506-delta)

- Review state: **PARENT REVIEW PENDING; this worker assigns no final
  PLAN-READY/PLAN-KILL verdict.** Parent will dispatch three independent,
  blinded plan reviewers (Opus-lens, hostile, security) against this committed
  revision and determine the terminal plan verdict.
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
  enforcement half is still open: no production ACCEPT exists on the diverted
  path (see §4 absence proofs).

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

25 of 33 files changed since the bridge; 8 are unchanged. This census is the
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

Thus 25 changed + 8 unchanged = all 33 Sep-20 commit paths. The change classes
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
| `userspace-dp/src/afxdp/poll_descriptor/mod.rs` | 60; `ec59234a1` fragment lifetime hardening | The ordinary packet path calls `evaluate_policy_result_with_icmp` (`:3992`); its fragment/policy order changed materially. Re-derive G3 consult order at P2; do not transplant the D11 worker entry into this path blindly. |
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
  verdict→`tx_delegated` split. The D11 attestation arm
  (`dispatchAttestEligible`, `pipeline_attest_10484.go:778-797`) is narrow and
  selector-armed only; ordinary frames stay deny-only. **This is the original
  defect, still open.**
- S9.5 INPUT (D12a-A): `ADMIT_INPUT_HOOK=6` refusal stands; **no
  `InputPermitCommitter` / `CompletionInputReady` anywhere**; D12a-C1/C2 proof
  cells not run.
- M1: no `xpf-usp1` exclusion in any `pkg/routing` rule manager (negative
  grep) — RPDB non-steering unproven, likely false under PBR/FBF.
- M2: no main-table egress oracle (no post-write domain confirmation;
  `delivered` counts fence matches, not egress table).
- M3/M4: `ingress_prefixes` frozen-membership enforcement + commit
  revalidation, and shared-device hook/conntrack inventory, not found outside
  design text (verify at P2 slice time; coarse VRF-enslaved refusal exists).

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

- Files: `userspace-dp/src/session/{discriminator.rs,key.rs,lookup.rs,mod.rs}`
  + HA wire codec (`routing_domain_wire.rs` + Go mirror) + protocol floor bump
  (both planes lockstep, exact-equality handshake; current v35).
- Work: `Ipsec(if_id)` class (forward + reverse arms), cross-discriminator
  alias index (bounded, multiplicity/eviction/generation checks), ambiguous-
  reverse refusal, unknown-tag fail-closed import, E9/E10/E30 mapping.
  Follow the `Pptp(handle)` precedent (direction-symmetric derived handle,
  own wire-tag window) — do not build the discriminator from a
  direction-varying packet value (#8382 lesson).
- Acceptance: forward separation; reverse unique/ambiguous/native-miss;
  unknown-tag import refusal; HA wire round-trip; unit cells fail-on-revert.

### P2 — S9.5 FORWARD permit join (closes the original defect)

- Files: `pkg/nfqueue/pipeline.go` (replace the `V1PermitSuppressed` deny
  with a policy-permit-to-q0 join; the held NFQUEUE original remains terminal
  `VerdictDrop` after completion, including written and uncertain outcomes);
  `pkg/nfqueue/reinject_socket.go` (existing submit/completion authority);
  `userspace-dp/src/slowpath.rs` and
  `userspace-dp/src/slowpath_reinject_9506.rs` (join worker policy Permit to
  the single `tx_delegated` q0 writer and report its terminal outcome);
  worker stage order (`afxdp/poll_descriptor/`, G3 consult order);
  `pkg/routing/{routes,routing}.go` (D_usp1/main-254 inventory, ECMP
  ownership, frozen `ingress_prefixes`); `pkg/daemon/ipsec_reinject_supervisor.go`
  (owner/lease commit); `pkg/ipsec/policy.go` (selector provenance for
  M3); metrics/witness join.
- Verdict contract: a policy permit is **not** `nfqueue.VerdictAccept`.
  P2’s permitted forwarding path is a successful q0 write; the original held
  NFQUEUE skb is terminally DROPed so the same frame cannot also continue
  through the kernel path. Definitive q0 refusal rolls back state exactly
  once; ambiguous/timeout completion is possibly-emitted, is never retried,
  and still terminally DROPs the held original. Any alternate design using
  NF_ACCEPT must first replace the q0 path and prove there is exactly one
  forwarding path for every result.
- Work: FORWARD session/NAT state provisional until the q0 write linearizes
  commit. Re-ground G3 order against #10679 and outer-claim against #10516 at
  slice time (do not copy Sep-20 assumptions).
- Acceptance: the issue's bar — denied AND permitted IPv4/IPv6
  decrypted-ingress flows with policy/session/counter evidence, and an
  observed single-path outcome (one q0 write plus original DROP, never both
  q0 write and NF_ACCEPT); HA + MTU behaviour, pricing gate (same-thread
  ~111ns or batched B>=3), M1–M4 must-proves or authorized scope cuts,
  fail-closed at every intermediate.

### M1–M4 must-proves (kill-conditioned, owned by P2/G5)

- M1 RPDB non-steering: live proof on loss cluster that no RPDB rule steers
  q0 ingress off main, or a V1 config gate refusing PBR/FBF coexistence —
  else K2 re-plan. Currently ABSENT (§4.3).
- M2 egress oracle: post-commit confirmation of q0-egress domain. Currently
  ABSENT. Without it, `delivered` is a fence-match witness, not an egress proof.
- M3 overlap/domain admission + commit revalidation: expected-domain stamp,
  route-resolution and commit-time revalidation incl. the §5.4 M3
  cross-tunnel-source cell (A-stamped frame with B-only inner source →
  E21 DROP-and-count, no shared-q0 fallback).
- M4 shared-device inventory: hook/conntrack/RPF/martian/`accept_local`
  inventory for the q0 shared device.

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
  `test/incus/*`, zero product overlap) + per-round attested exe on both
  firewalls. T12 structural cells flip VOID→MATCH with archive-verbatim
  ATTEST/RESTORE/SUMMARY; G2 consumer cells stay VOID until P2 (recorded
  dependency: they need `delivered>0` by construction).
- V2 post-P2: consumer round with permits flowing — `delivered>0`, per-shape
  stage rates, B>=3 economics, memory accounting (skbs→verdict queues→TUN),
  teardown-from-source, fragment head-of-line cost.

### Scope cuts (explicit)

- Single-writer q0 + `tx_delegated` sharing + limiter proof-or-split stays a
  must-prove cell (G1/T8), not a P2 refactor, unless the cell fails.
- `logical_ingress.rs` and `policy.rs`: reuse as-is per design (extend only
  with all-fields-required params / call-site flag respectively).
- No harness files in product slices; no new harness in G5.

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
- R4 — Protocol-floor skew on P1 tags: v35 exact-equality means a one-plane
  bump bricks mixed-version pairs fail-closed (safe) but also bricks the P1
  slice's own upgrade path if floors are wrong. Mitigation: lockstep bump +
  immutable per-feature floor + mixed-version matrix cells (§5.6 procedure).
- R5 — M1/M2 kill polarity: if RPDB steers q0 under PBR/FBF (likely) or the
  oracle proves unbuildable, V1 scope must cut (config gate) or K2 re-plan
  triggers. Mitigation: M1/M2 proof cells scheduled inside P2, not after;
  owner pre-authorizes the config-gate cut.
- R6 — D12a boundary creep: pressure to permit stateful INPUT without the
  Option B atomicity proof (NF_ACCEPT vs session publication not atomic).
  Mitigation: hard boundary — stateful INPUT misses stay E37; any Option B
  claim needs a proven two-resource prepare/finalize protocol + owner sign-off.
- R7 — Single-writer/limiter coupling: adjudicated + delegated share
  `tx_delegated` + one `RateLimiter`. If the proof-or-split cell fails, P2
  grows a queue split. Mitigation: cell runs early in P2; split is the
  pre-authorized fallback, not a redesign.
- R8 — Live-proof dependence: S9.7/M-cells/V2 need the loss cluster with XFRM
  SAs + traffic + attested exe on both firewalls. Prior rounds burned the
  attestation budget on wrong-binary/fixtures-missing VOIDs. Mitigation: V1
  structural flips first (cheap, no permits); executable attestation before
  any fixture-dependent round; budget the rounds explicitly.

## 7. Test plan

Per slice (each cell fail-on-revert; RED-on-revert evidence required in the
slice commit's Validation section):

- P1 cells: forward separation (two `if_id`s, overlapping 5-tuples → distinct
  sessions); reverse unique/ambiguous/native-miss; wire round-trip incl.
  unknown-tag import refusal; alias-index multiplicity/eviction/generation;
  E9/E10/E30 mapping. Revert check: removing the `Ipsec` arm must re-merge the
  separation cells (FAIL).
- P2 cells: zone-map matrix (zoned/unzoned/ambiguous/cross-spelling/
  duplicate-if_id/stale); Go hook pass/drop/nil/stale/shadow matrix; admit
  codes (each new code + unknown-code refusal); supervisor committer matrix
  (incl. `Accepted+error`, timeout-uncertainty no-retry, retained-handle only
  pre-committer); route-domain identity (exact D_usp1 vs other-domain E22);
  M3 cross-tunnel-source E21 cell; taxonomy fault-injection for every touched
  E-row (counter+event exactly once, no unmapped terminal). Live: denied +
  permitted v4/v6 flows with policy/session/counter evidence; HA failover +
  MTU/fragment behaviour; pricing gate (same-thread or B>=3).
- P3 cells: D12a-C1/C2 proof cells (must PASS before any INPUT permit ships);
  stateless-shape matrix; stateful-miss E37/E59 DROP matrix.
- V1/V2: T12/G2 rounds per `docs/log/9506-observe.md` — archive-verbatim
  ATTEST/RESTORE/SUMMARY, restore/residue clean, per-round attested exe.
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
3. **Can M1 (RPDB non-steering) pass on any realistic config, or is the V1
   config gate (refuse PBR/FBF coexistence) the only shippable shape?** The
   design admits the premise is "UNPROVEN and likely FALSE". KILL POLARITY: if
   the gate is unacceptable to the owner AND the proof fails, K2 re-plan
   triggers and this delta is dead. Assessment: gate is pre-authorized in §5;
   needs explicit owner confirmation before P2 codes against it.
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
