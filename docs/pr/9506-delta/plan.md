# 9506 delta plan: ship P-MECH permits on the current master (research/9506-delta)

- Review state: **v15 micro-revision; parent re-gate pending; this worker assigns
  no verdict.** V14 gate was NEEDS-MINOR 3-of-3; this revision closes its
  four residuals (R3-ANCHORS; Host P1 row-4/drift and P2 routing; Sec F1
  stall-window composition/counting). V14's prior record: Round thirteen at
  `0705fc8b2` returned NEEDS-MAJOR 2-of-3 + NEEDS-MINOR (Opus R1/R2/R3:
  FRR guard contradicts the
  immutable-q0-FIB invariant; M3 silently replaces the canonical
  route-derived contract; tip audit falsely claims no-impact through
  `2ccea8434` — Host P1/P2: OPEN-vs-mutation predicates contradict;
  structural attestation scheduled after dependent live entry — Sec
  B1–B6 minor: M1 wording/exposure, Q2 cells, kernel-bits binding,
  LANDED-matrix rule, Gate-2 recovery wiring, supervisor/handoff liveness).
  That v14 revision closed all eleven with no deferrals: ONE
  normative per-table/per-protocol FRR/FIB mutation-authority table
  (xpfd sole AUTHORIZED writer inside the owner-approved support envelope;
  unexpected external writers remain detection-bounded; R/A/K audit-only;
  zebra replacement/withdrawal attempts refused); M3 as an EXPLICIT contract
  (owner-approval flag, 0/0 refusal, no route-ownership role,
  disagreement/migration rules, superseded canonical clauses, four
  distinguishing cells); tip-impact addendum through `2ccea8434`
  (snapshot-floor composition, queue/socket-write + reconnect
  consumers, holder/restore/reseed census, re-anchored callsites)
  PLUS a post-pin audit to observed `0ab1c7d87`; ONE authoritative
  S4 OPEN-vs-mutation decision table (durable-freeze vs mirror vs
  ancestor; REOPEN vs NEW-GENERATION admission) with three
  distinguishing fixtures; V1a structural attestation split BEFORE
  P1/P2 live entry (§§1/5/6/7 synced); all six Sec minors as
  doc/predicate/cell fixes. Credited designs held EXCEPT M3 source
  provenance (explicit amendment, §5 M3-AMEND, owner approval
  required before P2 permit code). The parent will re-dispatch the
  blinded gate against this committed revision.
- Date: 2026-09-28. Worktree `/var/tmp/worktrees/9506-research`, branch `research/9506-delta`.
- Pins: `origin/master = 0ab1c7d87` observed (v14; R3 addendum through
  `2ccea8434` replaces the v13 no-impact claim — §4 drift base stays
  `028c4e4e2`; post-pin `2ccea8434..0ab1c7d87` intersection-audited,
  §9; cited-file hits re-anchored, no silent semantic breaks);
  Sep-20 code tip `b71c52d60`
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

Remaining slice order (v14: V1a attestation split out first — Host P2):
**V1a(structural attestation prereq) → P1 → P2 → V1b(consumers) → P3 → V2**.
F1 is done. P2 is the issue-closing slice; V2 is the pricing-gate proof.
#9506 stays OPEN until P2+V2. No P1/P2 live-entry round may report PASS
without the V1a prerequisite (source-bound manifests + running-process
hashes for BOTH `xpfd` and `userspace-dp` on BOTH firewalls + exact kernel
member `uname`/package rows/live Kconfig and classifier identity; the
kernel identity is the approved version/config tuple, NOT a runtime byte
hash, with same-version/different-binary integrity explicitly out of model
per the allowlist §6). A mismatched userspace-dp artifact FAILS the
prerequisite and VOIDs every dependent gate. Permit-dependent consumer
flips stay post-P2 in V1b.

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
  an unbounded detection window; no periodic FIB re-read exists either
  (ENOBUFS overflow and resubscribe gaps are mark-only,
  `daemon_route_listener.go:169,155`). No FRR render gate exists (xpfd
  renders `frr.conf` managed sections but owns no zebra hook; `ApplyFull`
  never calls the `Get*` readbacks), and `actuateLearnedRouteRefresh`
  republishes kernel/FRR route events WITHOUT `BumpFIBGeneration`
  behind a 1s/3s coalesce (`daemon_route_listener.go:232`,
  `purge_ids` is currently callerless but removes
  `WriteStarted` unconditionally (`:1310-1340`); `drain_timed_out` is
  test-only with a prefix-revisit starvation shape (`:1476-1512`,
  budget 64 of depth 128, front-requeue); no reaper thread exists.
  Slowpath writer `JoinHandle`s are discarded at spawn
  (`slowpath.rs:829-846`, `SlowPathReinjector` `:655-665` keeps
  senders/cores only); no `show ip/ipv6 protocol` shell exists
  (`GetRouteMapList` shows defs only); no authority/marker files exist
  under `/var/lib/xpf`.
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

### 4.5 v14 impact addendum: exact `2ccea8434` peer-snapshot change and post-pin intersections

Round-13 R3 is closed by this addendum; §4.1–§4.3 remain explicitly bounded
through `028c4e4e2` and are not re-described as a current-tip audit.
The previously claimed “zero cited paths” for `fd32d2df5` and
`2ccea8434` is withdrawn: the latter directly changes the M3-cited
`pkg/daemon/daemon_apply_commit.go` and `pkg/daemon/daemon_ha_sync.go`;
the former directly changes the allocator/HA holder path underlying the
reserved quarantine bit.

| Change | Re-anchored consumers at observed `0ab1c7d87` | Required P-MECH composition |
|---|---|---|
| `2ccea8434` peer-snapshot authorization (`peer_snapshot_protocol_gate_6650.go:34-120`) | Commit preflight includes plain and confirmed commits (`daemon_apply_commit.go:274-288,876-889`); `pushCommittedConfigToPeer` (`:493-527`) + revalidation; active snapshot/reservation and queue (`daemon_ha_sync.go:464-486,519-590`); reconnect/retry reconciler (`:705-820`); receive-side HA `handleConfigSyncWithAncestry` (`:880-913`). | M3's v36 shape floor must be included in every preflight and reconnect/retry decision. Compose the required floor as the maximum of ingress-prefix, multi-zone and every other concurrently-required feature floor. Preserve connection epoch + selected `SessionSync` capability authorization through the queue. |
| Final queue/socket boundary from `2ccea8434` | `SessionSync` final peer-state/active-connection check is under `peerSnapshotProtocolWriteMu` (`pkg/cluster/sync_conn_config.go:320-335`); `QueueConfigWithPeerSnapshotProtocolAtGeneration` begins at `:346`. | The M3 prefix floor is a required operand to the atomic queue check and final socket write; an earlier daemon preflight alone is insufficient. A reconnect or capability change between auth and write withholds the text and leaves reconcile unclaimed/retryable. Do not lower the floor when multi-zone and ingress-prefix features coexist. |
| `fd32d2df5` (#11478), plus `3be469bc3`/#10788 and `01879c222`/#10789 holder restore | `AllocatorHolderSnapshot` (`:221-224`) captures the published RuntimeView's SNAT/NAT64 holder masks (`reserve_synced_translation` `:340-437` in `session_import.rs`); `rollback_rejected_mirror_import` (`:439-573`) restores the incumbent allocator reservation, with worker loops at `:503,533` (both `0u32..128`); `restore_rejected_forward_mirror` (`:575+`) restores the forward BPF mirror. Atomic allocator capture is `CapturedLiveGuard` (`nat/allocator.rs:1827-1831`) + `capture_and_replace` (`:2017-2045`); retained allocator reseed is `reseed_retained_from` (`:4086-4223`), NAT64 prefix reseed `nat64.rs:938`. Current HA rollback interprets every bit `0..127` as a worker. | The quarantine census covers capture, refused replacement/rollback, worker-holder reconstruction, BPF mirror restoration, allocator reseed, NAT64/SNAT, worker retirement, and release/expiry. Reserve bit 127 exclusively for quarantine; worker restore covers 0–126 only; keep bit/HOLD through refused HA replacement. The §5 quarantine cell is mandatory. |
| Post-pin routing/allocator/lifecycle intersection, `2ccea8434..0ab1c7d87` (11 commits; 309 paths in total) | `8413be3a5` adds `UnbindInterfaceFromVRFs`/`LinkSetNoMaster` (`pkg/routing/vrf.go:240`), a route-domain writer added to M1. In `daemon_flow.go`, `RouteReplace` is now `:608,:689` and `RouteDel` `:740`; the `8413` flow/routes diff is the claim-helper rename, not a new route writer. `5c7c57c54` adds API-auth hashing to `Store.SyncApply` (`configstore/store.go:993`) before the still-required lenient compile (`:822-845`); M3 validation must remain in that compile. `0c3d0b7a0` adds bounded idle-lease import state in `nat/allocator.rs`; `20c731bf1` adds persistent-NAT clear fences and allocator carry (`carry_persistent_nat_clear_fences_from`); both are additional quarantine-preservation/cleanup consumers. `b100d557f` changes the HA watchdog cleanup portion of `daemon_run_shutdown.go`, not the #9506 helper-stop/join/flag-writer quiescence order. `1f436241f` adds host-input warning/flush logic to `daemon_apply_commit.go`, not the peer-snapshot authorization check. | The post-pin intersections were path-checked and the cited functions re-anchored; specifically re-review M3's post-hash lenient validator and quarantine survival across idle import, persistent-clear carry, helper shutdown and allocator reseed. New q0 route-domain unbinds are refused through the same S4 pre-effective boundary. |

The effective snapshot floor and authorization are a single end-to-end
contract: `peerSnapshotProtocolAuthorizationForConfig` captures the selected
connection/capability (`peer_snapshot_protocol_gate_6650.go:40-64`),
`revalidatePeerSnapshotAuthorization` rejects stale observations (`:82-120`),
and the SessionSync queue repeats the minimum-floor and active-connection
check while holding the final-write mutex. Both plain/confirmed commit and
reconnect-reconcile entry points must pass the composed floor. Config text and
active tree continue to be sampled atomically before queue reservation; no
socket I/O is moved under the config serializer. This addendum does not claim
that code exists for M3: these are P2 design and acceptance obligations.

## 5. Design: minimal viable delta

Lane order (F1 done): **V1a(structural attestation prerequisite) → P1 → P2 →
V1b(consumers) → P3 → V2** (V1a/V1b split per §5 V1; §1/§6/§7 sync).
Each slice is separately reviewable and fail-closed; the fail-closed-at-every-intermediate claim remains qualified until all §7 P1-entry Q2 bypass-hunt cells PASS. The file list is anchored to design §5.2 and re-grounded to master:
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
  Live-owner-lost-completion converges here with ONE authoritative rule
  (option A — no slice-time choice): a pre-park core `WriteStarted` is
  NONTERMINAL until writer death is proven. Deadline expiry transfers
  OWNERSHIP ONLY (worker→reaper CAS under core `inner`, setting new
  `Entry.owner` + `transferred` beside `connection_id` — no owner fields
  exist today, `:624-632`): the entry STAYS `WriteStarted`, stays visible
  to the same-inner-lock fence scan, and is NEVER terminalized via (d)/(c)
  while the writer lives. A live owner whose completion is otherwise lost
  can NEVER self-finalize to Written (no `IoRelease` proof). Late
  `resolve_write` after transfer reaches `Terminal` via REAPER-COORDINATED
  resolve (new transferred arm: lease + `WriteStarted` match with
  `entry.transferred`, terminalizing through the coordinated pair — never
  rejection-with-emission, never an unproven `Refused`/`Cancelled`;
  `Done`→`Written` since a terminal `WriteResult` IS the release fact,
  `Deferred`→`Uncertain` with the obligation retained). Writer death is
  proven ONLY by the SLOWPATH WRITER'S OWN join — NEVER by
  `join_worker_after_termination`, which joins AF_XDP adjudicator workers
  (`:1427-1459`, caller `coordinator/mod.rs:1037-1052`) while the
  `tx_delegated` TUN writer is a separately spawned `slow_path_worker`
  (`slowpath.rs:829-846`) whose `JoinHandle` is discarded today (CHOSEN
  fix, option A): handles live in a SHARED writer-handle registry (new
  `WriterHandles` struct holding `Mutex<Option<JoinHandle>>` per outlet,
  `Arc`-shared between `SlowPathReinjector`, coordinator teardown, and
  d11-reaper — shared so NO path can drop a handle silently; the reaper
  NEVER Arcs the reinjector itself, which would retain senders and wedge
  its own join), installed in `new()` on `Ok(join)` for BOTH outlets
  (`None` in `new_without_worker_with_core`; reinject-socket
  retained-handle precedent `reinject_9506.rs:269-270`,
  `NeighborManager` stop-and-join precedent), and each core `Entry`
  records its writer (`WriterId` newtype beside `owner`, installed at
  `pre_write_check` via a new explicit `writer` parameter — the delegated
  worker is the sole producer today, and the parameter (not a hardcoded
  outlet) keeps that attribution exact under any future second producer).
  LIFECYCLE (every path owns its handles — no silent discard; all names
  below are REAL interfaces — `FallbackWhenNone` exists nowhere and is
  RETIRED as vocabulary). OWNERSHIP BUNDLE (CHOSEN): the writer senders
  (`tx`/`tx_delegated`, new `Option<SyncSender>` fields), the writer
  `JoinHandle`s (new retained fields — today DISCARDED at
  `slowpath.rs:811-823` trusted + `:834-846` delegated, threads
  detached), the d11-reaper handle + heartbeat, and the op→writer
  bindings are ALL owned by the `SlowPathReinjector` incarnation.
  PRESERVED-INCARNATION DISCIPLINE — Option A SELECTED (P3O-01a;
  forced, not preferred): `stop_inner(false)` NEVER destructively
  shuts the bundle down — the preserved-Arc path
  (`teardown.rs:81-93` clone + `snapshot.rs:641-658` republish) keeps
  serving on a LIVE object, and inserting destructive shutdown at the
  common point would republish an object with no senders + joined
  writers. Option B (stop-and-reconstruct-never-republish) is REJECTED:
  always-reconstruct reintroduces the fixed-name TUN recreate race
  the preserved path exists to avoid (`teardown.rs:81-85`). Reconcile
  generation change = GENERATION FENCE (retire old D11 generation →
  STALE→DROP at admit + epoch fence via the M1 sequence scoped to the
  old generation; preserved writers keep serving new-gen work while
  in-flight old-gen `WriteStarted` drain under the still-effective old
  authority per M3 drain-then-effective). Destructive `shutdown()`
  runs ONLY on: full `Coordinator::stop`/disarm, process exit, and
  else-arm replacement (`old.shutdown()` BEFORE new publish);
  `stop_inner`'s slot (between D11 join `:1052` and status snapshot
  `:1088`) runs the GENERATION FENCE, never the destructive path.
  CONSTRUCTION (`SlowPathReinjector::new`, `slowpath.rs:805`): spawn
  trusted → spawn delegated → spawn d11-reaper (new) → handshake
  (`:866-888`) — all three spawns via new `spawn_named_worker()`
  (`cfg(test)` failpoint seam). Failure teardown per site, all
  join-before-return, via shared `abort_construction()` (drop
  senders, signal+join every SPAWNED thread, death-scan-asserts-
  empty): second-spawn `Err` (`:846`) → drop trusted sender, join
  trusted handle (prompt: `recv`-`Err` exit; reaper not yet
  spawned), THEN `Err`; handshake `Fail` (`:875-885`) → drop BOTH
  senders + STOP the reaper (named mechanism: writers exit on
  `recv`-`Err`, the reaper ticks on `park_timeout(1ms)` so stop
  is `reaper_shutdown: AtomicBool` store + `reaper_thread.unpark()`
  → reaper observes flag and exits — THREE live threads at Fail,
  all three joined) → take+join BOTH writer handles + join the
  reaper handle, all outside locks, death scan asserts empty
  (pre-publish — NOTHING submitted yet), THEN `Err`;
  reaper-spawn `Err` → drop both senders, join both handles
  (reaper never spawned), THEN `Err`. No leaked reaper is
  possible post-fix (dual-reaper sweeping need not be
  analyzed); backstop if one ever leaks despite this:
  `ACCOUNTED` first-terminal-wins makes a double commit a
  no-op second `false`, never a double terminal.
  (`RingWriter::new` `io::Result` failure is NOT construction
  failure: the sync arm takes over per `classify_io_uring_write`,
  existing behavior.)
  Caller fallback on `new`-`Err` is the REAL `snapshot.rs:669-680`
  None-arm: `last_error` into `last_slow_path_status`, `slow_path =
  None`, NO authority publish (`:686` skipped) = q0 deny — this exact
  arm is what the construction-failure cells pin. `shutdown()` (new,
  idempotent, on `SlowPathReinjector`): disable enqueue → take/drop
  senders + store `reaper_shutdown` + `unpark` → take writer
  handles → join writers + reaper outside all locks → death
  decisions.
  DOUBLE-STOP (PINNED): slots `Done` → `Ok` no-op; slots
  `Pending` → wait-on-`joined_done`-then-`Ok` (loser semantics
  below). Last-Arc-drop without `shutdown()` is FORBIDDEN and
  detected (`Drop` checks shutdown-called + slots `Done`, bumps
  `shutdown_skipped_drop` alarm, never joins — fail-loud, since
  joining there could wedge; `Drop` cannot join with non-`Option`
  sender fields because field drops run after `drop()`).
  SHARED PENDING SLOT (P3O-01b/R9-SEC-12 — the post-join retry owner):
  per-handle `Mutex<HandleSlot>`, `HandleSlot ∈ {Empty,
  Live(JoinHandle), Pending{owner: Stop|Reaper, proof:
  Option<DeathProof>, probe_finished: bool}, Done}` + `joined_done:
  AtomicBool` + `done_cv: Condvar` (the named wait primitive).
  `take`: `Live`→`Pending{owner, none, probe}` (exactly-once
  winner); `Empty`/`Done`→no-op; `Pending`→loser path. The winner
  joins (stop: blocking `:175-176` precedent; reaper:
  ONLY-if-`is_finished` — prompt, never wedges) and writes the
  `DeathProof` INTO the slot, then COMMITS (coordinated
  terminalize + `Leaked` insert under the (c) trio, `try_lock`):
  success → `Done` + done + `notify`; contention → RETAIN (proof
  stays in the SHARED slot, never winner-local) and retry
  TERMINALIZE (re-read proof, NOT re-take): stop-winner spins
  bounded (yield, ≤10ms) then ESCALATES to blocking ordered
  acquisition (deadlock-free per the global (c) order —
  guaranteed completion, no hang); reaper-winner retries next
  tick. `joined_done` is set ONLY after the commit (terminalize
  + row insert atomic) — never after join alone. LOSERS:
  stop-loser (`Pending{Reaper}`) waits `done_cv` in 5ms
  (`IPSEC_INNER_ACK_DEADLINE_NS`) rounds with heartbeat patience
  (reaper `last_full_service` advancing → wait on; teardown never
  proceeds to snapshot/close before done); heartbeat-stalled →
  STEAL: stop takes ownership and commits from the slot proof
  with blocking escalation (no re-join — join already done);
  proof-absent + `probe_finished` + owner dead → commit on
  probe-evidence + `STOLEN_COMMIT_ZOMBIE` gauge (the handle died
  with its owner; the thread DID exit — `is_finished` has no
  false-positive for exit — reclamation is skipped, resources
  freed at process exit). DONE-CHECK-THEN-ABANDON (R9 Host-8 —
  a wedged-not-dead original winner resuming after a steal must
  NOT double-commit): EVERY slot access (proof-write, every
  retry re-read, commit) re-checks slot state under the slot
  mutex FIRST — `Done` (or owner ≠ me) → ABANDON (drop local
  handle/result, no proof-write, no commit). A stale proof-write
  into a `Done` slot is therefore impossible by construction,
  and exactly-once holds across steal+resume. TOTAL BOUND (no
  infinite patience — heartbeat-advancing ≠ commit-progressing
  under a wedged lock holder): `STOP_LOSER_WAIT_MAX_NS = 1_000_000_000` (1s, new
  const); exceed with slot still `Pending` → `TEARDOWN_COMMIT_
  STALL` alarm + process ABORT (fail-stop — NEVER proceed
  without death decisions); recovery is the (g) helper-handoff
  unclean path (restart → fenced generations → re-admit).
  Stop-WINNER spins ≤10ms (fast path) then escalates to blocking
  ordered acquisition (deadlock-free per the global order —
  guaranteed unless a holder is truly wedged; wedged holder wedges
  teardown = fail-closed + abort via the watchdog path). REAPER
  SELF-MONITOR: pending-age per slot (`Instant` at take);
  pending > 1s with no teardown in progress → `REAPER_COMMIT_
  STALL` alarm + deny-all (fence already BLOCKS on the stuck
  entry; operator recovery = helper restart → unclean
  handoff). Reaper-loser (`Pending{Stop}`) defers (stop
  completes promptly via escalation). REAPER LIVENESS:
  `catch_unwind` around the tick loop (panic → log + continue —
  the reaper never dies from logic panics) + heartbeat; the
  lateness watchdog (`now - last_full_service > bound` →
  deny-only + alarm) covers process-level stall. Stop-path takes
  unconditionally; a live-but-wedged writer wedges teardown —
  fail-closed (nothing publishes; teardown never completes
  half-armed), consistent with the in-tree supervision
  precedent. Death check order: `is_finished` gates the reaper
  scan ONLY (probe, never proof — `tunnel_supervision.rs:165-166`
  precedent); proof is `JoinHandle::join`, executed OUTSIDE all
  mutexes (join-under-`core.inner` deadlocks against live
  `pre_write`/`resolve`), after sender-drop (`rx.recv` `Err`
  exits the loop, `:1605`) or thread exit; the reaper takes
  `core.inner` only after quiescence, then terminalizes a stuck
  pre-park `WriteStarted` to `Uncertain` reason 58
  `WORKER_ORPHAN_HA` (CHOSEN over a new outcome value —
  wire-stable) AND creates a per-op `Leaked` row in the
  obligation store (the kernel may own a buffer submitted before
  death; the registry died with the worker), which permanently
  fences the epoch per (e)(iii). Late-resolve contract,
  death-race restated: a transferred `WriteStarted` reaches
  `Terminal` via reaper-coordinated resolve while its writer
  lives, or via the death-to-`Leaked` path after its OWN
  writer's join proves death — never via AF_XDP join alone,
  never rejection-with-emission, never an unproven terminal.
  Deadline expiry in a pre-park pause therefore BLOCKS the
  fence (no ack), raises deny-all + `STUCK_WRITER_CLOSED` counter
  + alarm (new counter; screen `event_emit.rs:338-355` NOTICE
  precedent), and reaches CLOSED via `finalizePermitClose` once
  the transferred entry resolves or is death-proved to `Leaked`
  — never silent effectiveness.
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
  obligation); record release at the `release_matching` funnel (`:462-471`,
  covering `reap_ready`, `reap_matching`, and `drain_for_teardown`).
  The SUBMIT→PARK window is covered by a SURVIVING RECORD, not a second
  registration: `pre_write_check` installs `WriteStarted` (`:1060-1062`)
  BEFORE the writer call, so the core `Entry` already spans
  submit→park→resolve under the fence's lock — and its ONLY remover is
  `purge_ids` (currently callerless; `cancel`/`shutdown` never remove it,
  `resolve` is same-thread synchronous). PURGE INTERLOCK (lands BEFORE
  any purge caller is wired): `purge_ids` (`:1310-1340`) gains a
  `WriteStarted` arm = SKIP — retain entry, flow-order position, and
  reservation, with a new skip counter; `Queued`/`Terminal` arms
  unchanged; `sweep_orphans` TTL (`:1297-1308`) likewise skips
  `WriteStarted`. Effect: resolve-after-purge is impossible; every
  `Proceed` reaches `Terminal` via `resolve_write`; a stuck
  `WriteStarted` on worker death stays pending until the (e) reaper
  transfer — never silently discarded. `WriteStarted`→`Uncertain`
  happens ONLY via `resolve_write` + `Deferred` verdict (single path,
  `:1079-1101` + `:2184-2197`). The obligation lives in a NEW
  `Arc<Mutex<BTreeMap<(ring_id,op_id), ObligationRow>>>` anchored at the
  COORDINATOR beside `steering_owners` (never reassigned, never dropped
  on replacement — the v8 reinjector-owned placement would lose `Leaked`
  rows with the old incarnation): cloned into each `SlowPathReinjector`
  incarnation (worker hot path: park/release), into d11-reaper (sweep),
  and into the fence path — OUTSIDE the core entries (destroyed by
  `ack_ready`, `:1223-1257`), the registry (drained by `Drop`), any one
  writer thread, and any one reinjector incarnation — so it survives
  core-ack + registry-drop + writer exit + replacement. The reaper
  NEVER Arcs the reinjector itself (that would retain senders and wedge
  its own join); it holds only the store Arc + handle-registry access +
  op→writer bindings. The `Drop` handler (`:336-359`) REPORTS
  each survivor as a per-op `Leaked` row there (replacing aggregate-only
  counting for fenced epochs; `RetainedCounters` stays as telemetry).
  Payload reclamation and the M1 Rust ack require `IoRelease.proved`;
  the downstream-skb gate stays INDEPENDENT after I/O finality. The
  fence examines BOTH the core `entries` (pre-park `WriteStarted`,
  same lock as `pre_write`) AND the obligation store (post-park
  unreleased I/O). LATER FIXTURE in TWO groups (no destroy-then-assert
  for pre-park cases). POST-PARK group — preamble destroys the core
  entry (ack `Uncertain` → `ack_ready` removes it): (i) target-CQE
  release clears the obligation; (ii) failed teardown leaves `Leaked`
  rows → fence ack FAILS; (iii) writer exit leaves rows → fence ack
  FAILS. PRE-PARK group — preamble RETAINS the core `WriteStarted`
  record (no destroy; purge interlock + nonterminal rule hold it):
  (iv) park→resolve window: `WriteStarted` BLOCKS the scan, then
  resolve/drain/ack proceeds; (v) pause after submission before defer
  + `purge_connection` before close → obligation RETAINED, mutation
  prohibited; (vi) expire the completion deadline in the same pause →
  ownership-only transfer, `WriteStarted` retained and fence-visible,
  BLOCKS (no ack) + deny-all + `STUCK_WRITER_CLOSED` + alarm, CLOSED on
  late coordinated resolve or death-proof to `Leaked`. Success clears
  exactly once in all cases.
  (c) ONE coordinated terminal/ownership decision across `ReinjectCore`
  + `ProvisionalJournal` (today disjoint: no `request_id↔token` map, and
  `resolve_write` checks only core state, `:1083-1105`): the S9.5 join
  stores the journal token in the core `Entry` at `register`, binding
  `request_id↔token`; ONE lock order `core.inner → journal.records →
  obligation-store`, with `try_lock` on 2nd+3rd and E23/E28-style refusal
  on contention (precedent: `IpsecInnerRouter::admit`) — the obligation
  store joins the order (it was absent in v8, leaving the death handoff
  unordered). Death terminalize + journal `transition` + `Leaked`-row
  insert commit atomically under ONE simultaneous hold of all three (no
  release between `WriteStarted`-terminalize and row insert — otherwise
  a fence scan lands in the gap with neither record visible and acks
  spuriously); the fence scan likewise holds all three simultaneously
  (no release between the core scan and the obligation scan).
  PRECEDENCE (R9-SEC-01): THIS paragraph is the sole authoritative lock
  scope for handoff commit and fence scan; M1 (4) and M3 SERIALIZATION
  implement it verbatim (an implementer following either lands here).
  Worker park/release/`Drop` paths take the obligation lock ALONE
  (verified: none nests it under core/journal today), so no
  worker-side inversion exists; `try_lock` failure on either path
  aborts that attempt fail-closed (no terminalize, no ack) — retry
  discipline per the LIFECYCLE pending slot (stop-winner escalates
  to blocking ordered acquisition, reaper-winner retries next tick
  from the shared proof; never re-take). TEST SEAM (R9-SEC-02 —
  deterministic, sleeps never proof): `cfg(test)`-only rendezvous
  gates at handoff pre-commit, scan pre-second-lock, AND handoff
  post-terminalize/pre-`Leaked`-insert (no-op in the correct atomic
  path — the hold never releases there — active ONLY in the
  split-commit mutant) plus a `std::sync::Barrier` two-thread
  harness; production compiles zero hooks. Tombstone `ACCOUNTED`
  is the exactly-once linearizer for counters/events;
  `resolve_write` rejects after journal finalization (checks token state
  too) — EXCEPT the ownership-transferred arm: `lease` + `WriteStarted`
  match with `entry.transferred` terminalizes through the coordinated pair
  (journal transition to the terminal phase in the same atomic commit), so a
  late writer resolve after deadline transfer still reaches `Terminal`
  exactly once instead of orphaning an emission.
  First-terminal-wins holds ACROSS the pair: whichever side wins, every
  late path (second `terminalize`, late `resolve_write` on a finalized
  record, late owner `transition`, verdict replay) sees
  `Terminal`/`None`/`ACCOUNTED` and returns false. Exactly one finalization
  per token under live-owner, lost completion, owner death, writer death,
  late completion, AND restart — no cross-record arbitration gap.
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
  PRE-PARK lost (deadline expiry, writer live) → ownership-only transfer
  per (a), entry STAYS `WriteStarted` and fence-visible, NEVER
  terminalized; POST-PARK lost/death/restart → conservatively COMMITTED
  as `Uncertain` committed-but-inaccessible, NEVER rolled back;
  pre-park PROVEN death (the writer's OWN join, never AF_XDP join) →
  `Uncertain`/58 + `Leaked` obligation row per (a); reclamation needs
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
  (e) Reclaim owner, deadlines, traversal, lateness, ceiling, quarantine (ALL
  CHOSEN, no slice-time invention): owner is a NEW dedicated `d11-reaper`
  thread, period `D11_REAPER_PERIOD_NS = 1_000_000` (1ms, new const) —
  independent of worker poll (covers idle workers) and writer threads
  (covers dead writers). Ack deadline is `IPSEC_INNER_ACK_DEADLINE_NS =
  5_000_000` (5ms, new const, matching the Go NFQUEUE `AckDeadline`
  default, `pipeline.go:181,318`). TRAVERSAL (fair, budgeted, cursor,
  allocation-immune pass boundary — the current `drain_timed_out` prefix +
  front-requeue STARVES tail [64,128), so it is REPLACED, not wired
  as-is): queues B=64/tick/queue + reaper-owned positional cursor per
  queue, rotate-and-restore-at-BACK (`push_back` in order, NOT `push_front`
  rev), advance pos by B mod len, ALL live queues served every tick,
  K=2 (128/64) UNIFORM — positional rotation has no exclusion window, so
  every entry present or admitted is examined within 2 ticks regardless of
  refill (refill appends beyond the captured boundary; the 128 cap bounds
  the pass); journal migrates `HashMap`→`BTreeMap` token-ordered,
  B=256/tick, token cursor `AtomicU64` range-from-cursor with CAPTURED
  HIGH-WATER MARK: each pass captures `hwm = next_token.load()` at pass
  start and services `(cursor, hwm)` in key order — tokens allocated
  mid-pass are ≥ hwm (monotonic `fetch_add`) hence EXCLUDED from this
  pass; on reaching hwm with no unexamined resident below it, the pass
  completes, cursor wraps (0 on empty map), and the next pass captures a
  fresh hwm. The boundary CANNOT advance with allocation by construction.
  BOUNDS SPLIT (a single K=2 does NOT cover mid-pass insertions — a token
  admitted after its rank passed waits out the pass remainder plus most
  of the next pass, up to 4 ticks): K_REPEAT=2 ticks for residents
  present at capture (512/256; LOW-TOKEN PROOF: resident t < hwm has
  fixed rank below hwm at capture — `ceil(rank/256)` applies ONLY to
  in-pass residents, never to tokens excluded from the captured pass —
  and retire+insert-higher only removes below-hwm others or adds
  above-hwm entries); K_FIRST=4 ticks worst case for mid-pass admissions
  (remainder ≤2 + next pass ≤2). Live records are HARD-CAPPED at 512:
  `register` refuses beyond cap (`:764-772`, existing refuse-new) and
  the refusal maps to NEW reason byte 63 `JOURNAL_FULL` (new E-row 40,
  validity extends to {5,6}∪[32,63] with the same decoder updates as
  61/62 — no silent admit past the K denominator, ever). Fence-expiry
  reasoning uses K_REPEAT (post-retirement admission is refused, so only
  repeat-service matters there); ack-deadline reasoning uses K_FIRST
  (4ms < 5ms deadline + action margin). Obligations B=512/tick
  composite-key cursor hygiene sweep (full 16k K=32 = 32ms, explicitly
  NOT lag-bounded) PLUS a per-epoch bounded fence check O(epoch rows ≤
  16k total cap — microseconds against the 5ms deadline),
  no cursor, on the fence path; tombstone/active Vecs scan
  ONLY on rare cold death-join + `debug_assert` len ≤ 512 + gauge, off
  the 1ms tick. Cursor state is reaper-owned (`queue_rr AtomicUsize`,
  per-queue pos map, journal token, oblig key — precedents: fair
  `session_delta` drain, `worker_manager` cursor, `bpf_map` slice
  outcome). LOCKS: single short holds per mutex per tick; producers
  keep try_lock-or-count (never block on the reaper); sole nesting is
  (c) core.inner→journal.records→obligation-store, try_lock on 2nd+3rd +
  refusal (death handoff and fence scan hold all three simultaneously;
  abort fail-closed on contention); poison split preserved
  (queue/journal `into_inner`, slab fail-closed); const assert B < CAP
  per budget (`worker_queue.rs:591` pattern). LATENESS (honest:
  tick count NEVER proves wall time for a delayable thread): the 1ms /
  5ms contract is structural per-store service proof (K-tick coverage
  with the cursors above: K_REPEAT=2, K_FIRST=4) PLUS fail-CLOSED on
  observed lateness — `now - last_full_service > bound`, tick overrun,
  or overflow poison → deny-only + alarm (mirroring
  slab/E23/E24/overflow precedents). Regression polarity pinned
  fail-closed on the ack path: `now` < enqueue/`first_held` = unprovable
  age → not-yet-expired for reaping but NEVER freshness proof for a
  fence ack. Fence-expiry predicate keeps the revised-bound form:
  `fence_expired(gen) := worker_set_retired(gen) AND now - retire_time(gen)
  > IPSEC_INNER_ACK_DEADLINE_NS + D11_MAX_SWEEP_LAG_NS`, with a new
  `retire_time` recorded at `retire_worker` — and the LAG term keeps
  K_REPEAT=2ms (not K_FIRST): post-retirement admission is refused
  (retired generations go STALE→DROP at admit, so no record can be
  admitted into a retired generation mid-pass), hence only repeat-service
  matters after retirement; K_FIRST=4ms governs the ack-deadline path
  (first visit + terminalize within the 5ms deadline, 1ms margin).
  Quarantine ceiling instantiates the EXACT existing constants:
  `min(STALE_SYNCED_CEILING_MULT × expires_after_ns,
  STALE_SYNCED_CEILING_ABS_NS)` (mult 3, abs 7d, `session/mod.rs:162,171`),
  measured from a new per-record `first_held_ns` with a
  `ReapStaleSynced`-analogous decision (`expire.rs:674` precedent) — PLUS
  a provisional cap `PROVISIONAL_HOLD_CEILING_NS = 60_000_000_000` (60s,
  new const): provisional D11 records never hold pinned bytes longer
  than 60s. Outcomes are SEPARATED: (i) logical reservation retirement
  → tombstone `ACCOUNTED` + counters + `Finalized` bookkeeping; (ii)
  physical buffer → freed/reused iff `IoRelease` proved, else deliberately
  leaked (`mem::forget` + per-op `Leaked` row + `RetainedCounters`);
  (iii) unresolved-I/O obligations are NEVER reaped by any ceiling.
  `Leaked` rows persist in the obligation store (bounded by
  `LEAKED_OBLIGATION_MAX = 16384`, the `terminal_tombstone` precedent)
  and permanently fence their epoch: no clean ack for that epoch ever;
  no descendant generation clears the ancestor, and OPEN/mutation stay
  refused until reboot retires the boot-bound epoch. An unreleased
  `IoRelease` ancestor blocks OPEN/mutation until target-write release
  or bound-writer death-proof, after which all remaining S4 gates still
  apply. A drift `ASYNC-SUSPECT` blocks OPEN until the S4 fence proves
  all old-epoch I/O final; only then may same-environment re-admission
  pass the ordinary S4 checks. The boot-current PERMUTATION-FREEZE
  continues to refuse step-6 mutation until reboot. A new epoch never
  silently discards an unresolved `Leaked` or `IoRelease` ancestor;
  store overflow sets a poison flag → ALL fence acks fail (deny-only) +
  alarm until operator reset. Crash cleanliness is a ONE-SHOT
  generation-bound marker with an INDEPENDENT expected-authority source
  (comparing the marker to itself would be
  vacuous, and a fresh supervisor's zero identity would freeze every
  clean restart): source is a NEW durable
  `/var/lib/xpf/ipsec-fence-authority` (`MkdirAllDurable` +
  `WriteFileDurable` 0600; content = status + canonical overlay fields
  + boot_id + HA epoch + install sequence + triple), updated
  ATOMICALLY (write-temp + fsync + rename + dir-fsync under the same
  flock; fsync error → abort WITHOUT rename; `*.tmp` ignored at
  read). Status ∈ {VALID, INVALID}; INVALID records are tombstones
  carrying a reason (below). WRITE SITES (EXACT census — no others):
  VALID on fence completion ONLY at the four reconcile ack sites
  (`ipsec_host_fence_reconcile_9506.go:237` hold install+readback,
  `:332` empty-authority ack, `:361` fallback ack, `:366`
  install+readback) — `wiring :1519`/`:1689` are PINNED TO INVALIDATE
  (both are `Store(nil)` on ambiguous-removal/quarantine-fallback at
  master; listing them as updates would establish authority where NO
  fence completed). INVALID (tombstone) on EVERY nil transition:
  `host_input_fence_9506.go:17` (bound INSIDE
  `setHostInputFenceOverlay` — covers ALL candidate-publish callers
  incl. restore-fallback), `:24` (bound INSIDE
  `clearHostInputFenceOverlayAfterAck` — covers the ORDINARY OPEN
  retire path), reconcile `:287`, wiring `:1519`, `:1689`.
  INVALID reasons: `nil-candidate-publish`, `nil-postack-clear`,
  `nil-restore`, `nil-ambiguous-removal`, `nil-shutdown-ambiguous`,
  `epoch-advanced`. The authority file, once created (first fence
  completion OR first nil — whichever proves the supervisor acted),
  is NEVER unlinked — only atomically rewritten — so its mere
  EXISTENCE is the durable ever-initialized signal; absence of a
  current ACK NEVER erases this boot's prior admission (FRESH-01).
  EPOCH-CHANGE TRIPLE FRESHNESS (R9: the four permit-record CAS
  sites — `revokeTransitPermitNonblocking` `:298`,
  `finalizePermitClose` `:340`, `tryOpenPermit` `:365`,
  `publishWatchSnapshot` `:435`): each successful CAS SIGNALS
  (nonblocking, cap-1 coalescing chan — revoke is CAS-only
  nonblocking for topology callbacks and must NEVER fsync) a
  dedicated `fenceAuthorityFlusher` goroutine, which rewrites
  same-status + CURRENT triple. The flusher NEVER creates the file
  (skips when absent — creation sites are fence/nil writes ONLY,
  keeping case-(1)'s "first fence OR first nil" exact; a pre-first-
  fence epoch CAS leaves absence intact and first-install admit
  stays sound — no fence ⟹ no submissions ⟹ no obligations).
  REQUIRED skip-if-stale: the flusher re-reads the file triple and
  skips when file ≥ current (`permitEpoch`, `watchGeneration`,
  `closeRequestSeq` lexicographic — all monotonic); without the
  skip a stale flush landing after the shutdown fence would desync
  the marker match. Soundness note: freshness is UNOBSERVABLE to
  decisions (the shutdown fence always re-establishes VALID+current
  pre-marker); misses fail safe as spurious marker-mismatch freeze
  — the lane must still bind all four sites, not invent fewer. PERSIST
  ORDERS (asymmetric, each justified): VALID writes are
  persist-THEN-publish (file first, then in-memory `Store`;
  persist fails → NO `Store` + `markRetry` + alarm — the fence
  simply doesn't complete). Nil writes are `Store`-THEN-persist
  (in-memory nil FIRST — safety-critical: ambiguous-removal must
  clear the ack even if the disk is dying; persist fails →
  LIVE-freeze-until-reboot: revoke if OPEN + bar OPEN + alarm;
  the stale-VALID file is harmless via no-marker-freeze).
  Flusher persist failure → alarm + backoff retry (decisions
  never depend on the flusher). Fresh-init rewrite failure →
  freeze + alarm, never silent admit. A crash mid-rewrite leaves
  either the old or the new version, both present, both freezing
  without a marker.
  Graceful shutdown completes the fence
  + writes the CLEAN marker (new `/var/lib/xpf/pmech-clean-shutdown`)
  at the end of `shutdownIpsecCapture` (`:1660`, after divert removal +
  fence ACK) or in `runShutdownSequence` immediately after it returns
  (`:144`), before dataplane `Close()` — past the point of no-new-I/O
  (fence hold + divert removed), so crash-after-write is still clean;
  content is `boot_id` + the active `(watchGeneration, closeRequestSeq,
  permitEpoch)` triple, `fsatomic.WriteFileDurable` + flock
  (`withEpochFileLock` pattern, no-pidfile rule). The marker is written
  ONLY on an EXPLICIT successful fence+removal verdict — never merely
  because `shutdownIpsecCapture()` returned (`void` today, failures only
  logged at `:1660-1699`): P2 changes it to return a new
  `ShutdownFenceVerdict{ok, reason}` collected from the fence-ACK and
  divert-removal results, and the marker writer requires `ok` (a failed
  shutdown certifies nothing — next start freezes). MIRROR BAR
  (Hostile-5 — daemon-restart evaporation): the marker writer ALSO
  requires the daemon freeze mirror CLEAR (`fenceFlagLive` unset);
  mirror SET (a flag write failed this run — the file CANNOT carry
  the freeze) ⇒ NO marker, verdict-not-ok-equivalent. Otherwise a
  failed RESET-from-absent/stale write → clean daemon stop (marker
  written) → same-boot restart (mirror cleared, file absent/stale)
  would take case-(3) CLEAN and admit OPEN+mutation WITHOUT the
  reboot retirement boundary for untrackable skbs (crash re-derives
  via case-(4); clean-stop is what evaporates). With the bar, that
  restart takes case-(4) (no marker + authority present) → freeze;
  the mirror clears ONLY at reboot-init, so no clean shutdown is
  possible while a freeze is file-unrecorded. QUIESCE ORDER (no
  post-marker flag write — event/audit loops AND the helper
  handoff, Hostile-3): (i) event/audit loops halt BEFORE
  `shutdownIpsecCapture` runs, so no drift/readback can land a flag
  write after the marker write; (ii) the helper is STOPPED (no
  respawn — shutdown bars the restart timer outright) and JOINED
  reaped with its exit hook + handoff record DURABLE before the
  mirror check (a helper crash/teardown-unclean exit in the
  marker-to-process-exit window with a sick-disk RMW failure
  would otherwise SET the mirror post-marker — file absent,
  memory cleared on restart → case-(3) false CLEAN); (iii) EVERY
  in-flight flag writer is JOINED, not merely signalled — a new
  `flagWriters` WaitGroup held across each flag RMW critical
  section (Add before flock, Done after), `Wait()` returns before
  the check; (iv) RE-VERIFY mirror-clear AFTER the helper join +
  `flagWriters.Wait()`, immediately before the marker write — any
  SET ⇒ NO marker (verdict-not-ok-equivalent). Post-(ii)–(iii)
  the writer set is EMPTY (loops halted, helper reaped, respawn
  barred), so re-verified-clear stays clear through the write.
  The shutdown proving
  fence runs UNCONDITIONALLY — even with a nil overlay (nil ≠ no
  in-flight I/O; the fence proves the negative) — so every marker write
  is preceded by a VALID authority rewrite; marker+tombstone is
  therefore unproducible by a clean path. STARTUP DECISION
  TABLE (evaluated in `startIpsecSupervisorLoop` BEFORE the tick
  goroutine spawns — no tick can open first — via new
  `resolveStartupAuthority()`, enforced again at
  `tryOpenIpsecPermitAfterFenceAck` which refuses unless startup
  resolved admissible): READ SEMANTICS (R9 P2-read — PINNED, no
  misread admits): ABSENT := `os.IsNotExist` on the path; any OTHER
  read error (EACCES/EIO/EPERM/…) on EITHER file → freeze + alarm
  (case-4-style until reboot; reboot retries the read — transient
  errors recover, persistent deny). `boot_id` source is
  `/proc/sys/kernel/random/boot_id` (reuse the `bootIDPath` const +
  parse from `pkg/cluster/sync_boot_incarnation.go:123-162`, NEVER
  the zero-on-error `localBootIncarnation` — a zero substitute would
  alias distinct boots): new strict `readBootIDStrict` (error or
  parse failure → error); resolve retries 3× with backoff, then
  freeze + alarm until reboot; every authority/marker/freeze write
  embeds write-time boot (write-time failure → persist-failure
  handling). TORN authority (unparseable, unknown status enum, or
  unknown version — newer versions freeze, never downgrade-admit)
  → TAMPER-equivalent freeze + alarm: crash-UNTORN is argued
  (rename atomicity + `*.tmp` ignored + fsync-abort-no-rename ⇒ a
  crash cannot tear the target; bitrot ≡ tamper, out of model —
  same trust as binary integrity), so torn means media/tamper, NOT
  crash. NAMED RECOVERY (the ONLY operator path, and it cannot
  clear a legitimate freeze): `xpfd reset-torn-fence-authority`
  REFUSES unless the authority file fails to parse (valid or
  INVALID records are never touched; absent file is NOT torn —
  refuse). ORDER (blocker: crash-safe sequencing): under the
  SAME flock as resolve/writers, FIRST durably write the
  `RESET-PENDING-REBOOT` sentinel recording the CURRENT boot
  (write-temp + fsync + rename + dir-fsync — the sentinel is
  COMPLETE before any unlink), THEN unlink ONLY the torn file
  (+ dir-fsync). Crash between the steps leaves sentinel +
  torn file → still freeze (torn rule fires; re-run is
  idempotent: torn still present → rewrite sentinel + unlink).
  Crash after unlink leaves sentinel + absent → freeze via the
  sentinel (NEVER first-install: `resolve()` checks the
  sentinel BEFORE the absent+absent case and freezes while it
  names the current boot). SICK-DISK-PLUS-REBOOT (explicit):
  sentinel write failed (torn intact, no sentinel) + reboot →
  STILL FROZEN — the torn rule fires pre-case-(2); reboot never
  clears tamper; recovery is re-run-when-healthy (disk fixed →
  command succeeds → reboot → admit). On boot change `resolve()`
  removes
  the sentinel and proceeds (absent+absent post-reboot →
  first-install admit — sound because the reboot retired all
  kernel obligations). Re-run with sentinel present + file
  already absent (no reboot yet) → REFUSE ("already reset,
  reboot required"). Torn marker → mismatch-freeze (never consumed;
  reboot unlinks stale markers). Cases: (1) authority file ABSENT +
  marker ABSENT + NO current-boot sentinel →
  FIRST INSTALL — and ONLY genuine first install reaches here: the
  authority file is created on the first fence completion OR the
  first nil-invalidation (whichever proves the supervisor has
  acted) and is NEVER unlinked thereafter, so absence means no
  fence ever completed AND no nil was ever recorded, hence no
  kernel obligations can exist (OPEN requires fence completion)
  → initialize fresh authority + admit normally. (2)
  authority.boot_id ≠ current boot (VALID or INVALID — a
  tombstone from a prior boot retires with the reboot like any
  other state, regardless of marker state) → REBOOT happened:
  kernel state is fresh, the retirement boundary has passed →
  FRESH INIT: unlink any stale marker, atomically rewrite fresh
  VALID authority (never unlink), establish fresh run identity
  via normal fence/census, admit normally — reboot NEVER
  re-freezes. (3) authority VALID + authority.boot == current
  boot + marker present + boot match + triple match vs the
  authority file → CLEAN RESTART: consume (read + unlink +
  dir-fsync via new `fsatomic.RemoveDurable`, absent-still-syncs
  `#5835` precedent, under flock), establish NEW run identity
  independently (fresh generation/epoch via fence/census —
  marker values validated then discarded, so nonzero prior
  identity reopens), admit. Marker+INVALID is INCONSISTENT (a
  fence completion rewrites VALID before any marker write, so no
  clean path produces it) → freeze as (4). (4) authority present
  (VALID or INVALID) + authority.boot == current boot + marker
  absent/torn/mismatched → CRASH (or crash-between-unlink-and-
  OPEN, or crash-after-nil-invalidation without a later
  fence+clean-marker, all observationally identical) → refuse
  OPEN (stay CLOSING) + write the boot-bound permutation-freeze
  flag (reason `crash-unclean`, current boot — R9 P1-freeze,
  self-clears on boot change) + alarm. There is NO operator
  command clearing a freeze in place — reboot is the ONLY reset
  (post-reboot fresh init reopens automatically); any manual
  state deletion outside reboot voids safety (operator-managed
  persistent state, same trust as binary/config integrity —
  equivalent to tampering, out of threat model).
  Fixtures: clean-stop→restart→crash→restart AND
  crash-without-prior-clean-stop AND clean same-boot restart with
  nonzero prior identity (must OPEN) AND crash→reboot→re-admission
  (must reach fresh admissible state) AND clean shutdown→reboot (must
  OPEN, stale marker discarded) AND first install (must init + OPEN)
  AND boot-ID mismatch with current-boot authority (must freeze) AND
  crash-between-unlink-and-OPEN (must freeze) AND failed/partial clean
  shutdown (verdict-not-ok → no marker → must freeze) AND
  mirror-set clean-stop (flag write failed → mirror SET → shutdown
  fence+removal OK but NO marker → same-boot restart takes case-(4),
  NEVER case-(3)) AND helper-crash-racing-shutdown (helper crash
  after loops-halt with sick-disk RMW failure → mirror SET →
  mirror re-check after helper join observes SET → NO marker →
  same-boot restart case-(4); plus post-marker-window assertion:
  helper provably reaped + respawn barred + `flagWriters` empty
  before the check, so no writer can land after it) AND
  crash-after-nil-invalidation (retire nil AND ambiguous nil, each: nil
  → tombstone present → crash, no later fence, no marker → must freeze;
  authority file EXISTS — absent+absent is unreachable here) AND
  normal-overlay-retire/crash/restart (OPEN → `:24` postack-clear →
  crash → same-boot restart → must REFUSE fresh admission) AND
  ambiguous-removal/crash/restart (`:1519` nil → crash → same-boot
  restart → must REFUSE) AND candidate-publish/crash/restart (`:17`
  nil → crash → same-boot restart → must REFUSE) AND
  nil-then-fence-then-clean (nil → later fence rewrites VALID → clean
  marker → must OPEN — tombstone cleared by proof) AND
  marker+INVALID-inconsistent (forged/coerced pair → must freeze) AND
  crash-mid-tombstone-rewrite (kill -9 during Store(nil) persist →
  either version present → must freeze) AND read-error freezes
  (EACCES/EIO on authority OR marker → freeze + alarm; reboot
  retries) AND torn-authority (unparseable/unknown-status/newer-
  version → tamper freeze + alarm; reboot does NOT clear; ONLY
  `reset-torn-fence-authority` + reboot recovers; the command
  REFUSES valid/INVALID/absent files; writes sentinel BEFORE
  unlink (SIGKILL-between-steps fixture: kill -9 after sentinel
  durably written, before unlink → sentinel + torn → freeze;
  kill -9 after unlink → sentinel + absent → freeze via
  sentinel, NEVER first-install; re-run idempotent; SICK-DISK:
  sentinel write fails → NO unlink, torn intact, command
  errors, still frozen; sick-disk-plus-reboot → STILL FROZEN
  (torn pre-case-(2)); ONLY post-successful-reset-reboot admits;
  re-run-when-healthy recovers)) AND torn-marker
  (→ mismatch-freeze, never consumed) AND boot_id-unreadable
  (3× retry → freeze + alarm) AND persist-failure outcomes
  (VALID-persist fail → no Store + retry; nil-persist fail →
  live-freeze-until-reboot + alarm; fresh-init-write fail → freeze)
  AND epoch-flusher cells (all four CAS sites signal; skip-if-stale
  suppresses a stale flush after a newer write; revoke path never
  blocks on fsync — measured, not asserted) AND freeze-flag cells
  (case-4 writes boot-bound flag; post-reboot mutation allowed again;
  stale-unlink-failure → refuse + alarm; stale-boot RESET on write;
  write-failure → live-freeze + sticky daemon mirror;
  hygiene-unlink-failure → mutation-SET + OPEN iff admissible)
  AND crash-during-fresh-init (crash after case-2 rewrite, before
  OPEN → case-4 freeze; NEXT reboot re-enters case-2 and admits —
  recovery, not loop) — no path reuses a consumed marker, and a
  genuinely clean restart reopens.
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
  v14 R3 holder census through `fd32d2df5` (#11478), re-anchored at
  `0ab1c7d87`: HA refused-replacement rollback captures/restores the
  incumbent holder mask in `AllocatorHolderSnapshot` (`:221-224`) /
  `rollback_rejected_mirror_import` (`afxdp/ha/session_import.rs:439-573`,
  allocator reservation restoration; worker loops at `:503,533`, both
  `0u32..128`) vs `restore_rejected_forward_mirror` (`:575+`, forward BPF
  mirror restoration); allocator capture is `CapturedLiveGuard`
  (`nat/allocator.rs:1827-1831`) + `capture_and_replace` (`:2017-2045`);
  `SourceNatReservationSnapshot` (incumbent reservation state) is the type
  at `:878` with `impl` at `:5947` (`holder_mask` `:5950`,
  `restore_metadata` `:5958`) — distinct from `PortAllocator::snapshot`
  (`:5676`, status returning `PortAllocatorSnapshot` `:6027`); retained
  allocator reseed is `reseed_retained_from` (`:4086-4223`), with
  corresponding NAT64 reservation/holder restore
  paths in `nat64.rs` and `nat/source/nat64_ports.rs`. Current HA restore
  loops interpret EVERY bit `0..127` as a worker. v14 reserves bit 127
  exclusively for `NatHolder::Quarantine`, caps worker IDs at
  `0..126` (`MAX_NAT_HOLDER_WORKERS=127`), and keeps the u128 width 128;
  snapshot/restore/reseed carry the quarantine bit separately from worker
  IDs, never as worker 127 and never clear it during a failed HA
  replacement. Add the whole path to the census: capture → rejected mirror
  publication → allocator restore metadata → NAT64/SNAT holder restoration
  → `retire_all_worker_holders` → allocator reseed/snapshot → release,
  rollback and expiry. Required cell: seed a quarantined SNAT and NAT64
  reservation, force strict HA replacement refusal after holder capture,
  restore the incumbent and assert bit 127/HOLD survives worker-mask
  reconstruction, worker retirement, ordinary expiry, and allocator
  reseed; the resource remains unavailable until its quarantine owner
  resolves it. Mutants that iterate `0..128` as workers or drop the
  reservation on refused replacement must fail.
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
  is the only post-restart state source. HELPER-INCARNATION HANDOFF
  (R9O-01 — the helper has an INDEPENDENT crash/restart lifecycle:
  `Manager` restarts it without restarting xpfd
  (`process_supervisor.go:303-407`, `process.go:304-322`, SIGKILL
  escalation `:601-611`), the socket client REPLAYS cached
  `announcePayload` on reconnect (`reinject_socket.go:93-112`),
  and `permitOpen` derives from the CONTINUING supervisor
  (`ipsec_capture_wiring_9506.go:646`) — a fresh helper's empty
  store would otherwise admit q0 under old authority and attest
  vacuous-clean fences for a generation whose I/O it never saw;
  XDP disarm + generation fencing + epoch rules do NOT cover
  this boundary). INCARNATION (bound at every handoff): `(boot_id,
  daemon_pid, procGen, helper_pid)` — `procGen` bumps on spawn
  (`process_supervisor.go:258`) and stop (`process.go:543`);
  `daemon_pid` confines verdicts to one daemon run. DURABLE
  STATE (two files): (i) `pmech-helper-handoff` (per-exit,
  overwritten each exit): `{boot, daemon_pid, old{gen,pid},
  verdict: clean{proof} | unclean{reason}}` — consulted on
  helper spawn WITHIN the same daemon run only; (ii) the
  boot-bound permutation-freeze flag gains `helper-unclean`
  entries `{gen, epoch, reason, at}` — cumulative per
  generation, honored across daemon restarts, cleared ONLY by
  boot change (the (e)(iii) ancestor rule: a prior unclean
  generation is never removed by a later clean verdict — only
  reboot retires it). EXIT HOOKS (all three): crash →
  `handleUnexpectedHelperExitLocked` (`:303`) writes
  `unclean{reason: crash}` + freeze entry + revokes the S4
  permit to CLOSING (new `noteHelperExitLocked` hook —
  re-open only post-handoff under a NEW generation);
  intentional stop/replacement → fence-FIRST (before the `:590`
  shutdown request, while the old helper is fully alive: full M1
  fence + `IoRelease` drain proven) then `clean{proof}` verdict,
  else `unclean{reason: fence-failed/timeout}`; SIGKILL escalation
  (`process.go:609`) → `unclean{reason: killed-during-teardown}`
  (kill precludes any verdict). REPLAY GATING: `Manager`
  UNBINDS the submitter on every helper exit; new
  `BindHelperIncarnation` re-binds ONLY after the handoff file
  resolves (clean: matching old incarnation + same
  daemon_pid + boot — replay + inherit; unclean/absent/
  cross-daemon: NO replay — `ensureSubmitLocked` returns a
  handoff-pending error pre-dial, fail-closed); a stale conn
  to a LIVE helper keeps its binding (incarnation unchanged).
  GATE WIRING (no dangling hook): new `PmechHandoffGate`
  interface (`NoteHelperExit`, `BindHelperIncarnation`)
  implemented by the daemon capture wiring, injected into
  `Manager` (nil-safe: nil gate = legacy/D11-only behavior,
  replay ungated — BUT P-MECH admission requires a non-nil
  gate + bound incarnation before OPEN, so no P-MECH permit
  ever opens ungated). BELT: the pipeline ALSO refuses
  P-MECH submits unless handoff-bound (explicit local error
  vs the helper's empty-authority refusal — redundant by
  design). AVAILABILITY BOUND: replay is refused only in
  the exit→handoff window (handoff completes in ms post-
  spawn; unclean needs no reboot for REPLAY — reboot retires
  the durable mutation freeze), and submits already fail while
  the helper is down today (no listener). This does NOT promise
  OPEN while an old generation has unresolved I/O: new work may
  be staged under a fresh generation, but the authoritative S4
  decision table below refuses `tryOpenPermit` until every ancestor
  is resolved/proven dead or reboot retires it.
  RUST SIDE: the new helper IMPORTS the daemon-announced
  fenced-generation set at announce (old unclean generations
  fence-FAIL forever in the new store); fresh-generation admission
  is conditional on the S4 table, never an ancestor bypass.
  DAEMON RESTART ignores the handoff file (total owner death per (g):
  sweep + HA import only) but HONORS freeze entries; same-environment
  re-admission may OPEN with durable file-set/mirror-clear only if no
  unresolved ancestor, while routing mutation stays barred. SHUTDOWN-JOIN
  (Hostile-3): daemon shutdown
  stops the helper (no respawn), JOINS it reaped with its exit
  hook + handoff record durable, then joins `flagWriters` — all
  BEFORE the mirror check+marker write per QUIESCE ORDER (the
  marker-to-exit window provably contains no live helper and no
  in-flight flag writer). Clean-restart exceptions bind old+new
  helper identities (file `old{gen,pid}` + current procGen),
  NEVER the Go run alone. (The task-exit-finality alternative
  — proving dead-helper kernel I/O final without durable
  state — is NOT taken: no such proof exists read-only.)
  Canonical mapping: ADOPT
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
- M1 trust boundary (AUDITED/DETECTED-writer contract — v14 B1): owned
  PREVENTION is claimed only for xpfd-owned mutations which rendezvous
  with S4 before effective change. Out-of-process writers are detected
  after change and are explicitly detection-bounded, not “sole-writer” or
  zero-observation safe. The owner-approved supported-configuration
  restriction and the FRR/Zebra route-authority policy in (5) define the
  admitted set; post-install revoke/R/A/K receives no exclusion credit.
  (1) Full in-process writer enumeration, `Clear`/`Reassert` included:
  `routing.Manager` facade — `CreateVRF`/`ReconcileVRFs`/
  `ReassertVRFMissTerminator`/`BindInterfaceToVRF`/
  `UnbindInterfaceFromVRFs` (`pkg/routing/vrf.go:240`, `8413be3a5`;
  `LinkSetNoMaster` changes route-domain membership and is refused while
  OPEN for q0 interfaces), `Apply`/`Clear` tunnels,
  xfrmi, bonds, reth (no-op apply), probe pins; `ApplyNextTableRules`/
  `ApplyRibGroupRules`/`ApplyPBRRules`; bands next-table window, rib-group
  30000-30999 + return 1500 + clear windows, PBR 31000-31999, VRF
  terminator 2000, L3MDEV 1000; daemon-direct mgmt-999
  `RouteReplace` (`daemon_flow.go:608,689`) + `RouteDel` (`:740`)
  at `0ab1c7d87`; `8413be3a5` flow/routes changes are claim-helper
  renames, not a new route writer; plus the `daemon_apply_routing.go`
  commit tail + republish/`BumpFIBGeneration`.
  (2) Kernel-default inventory per admitted OS image: priorities
  0/32766/32767 + l3mdev 1000 with exact match shapes (in-process code
  NEVER writes 0/32766/32767; `bake.py` bakes no routes/rules; networkd
  renders no `[Route]`/`[RoutingPolicyRule]`; `pbr_applied` + fibimport
  exclusions pin the known set). (3) Owned-vs-unowned MATCHING
  ALGORITHM: every xpfd install records `(band, priority, full
  selector, table, owner)` in the install inventory; a live rule is
  OWNED iff it tuple-matches an inventory entry exactly, else UNOWNED.
  (4) DETECTED-EXTERNAL-WRITER BOUND (v14 Sec B1): `RuleSubscribe` on
  IPv4+IPv6 is REQUIRED for RPDB writes (not sole-writer language); sync
  `ruleListFn` at every publish plus commit-tail reconciliation remain
  independent snapshots, with a periodic audit closing dropped-event gaps.
  Placement is the SUPERVISOR 1s CENSUS BRANCH (CHOSEN —
  not the 5ms branch: those are different select branches in
  `startIpsecSupervisorLoop` `:30-42`, and the 5ms order would run full
  netlink dumps every 5ms): the audit call sits in the `census.C` branch
  BESIDE `pollIpsecTopology` — before it, unconditional, never behind
  its unchanged-census early-return (`:147-181`), so periodic liveness
  cannot be skipped. (`statusLoop` is disqualified: exits on `proc==nil`
  `:302`, skips the whole tick on `linkCycleInFlight` `:329`, blocks on
  `requestLocked` `:341` with 67s-reachable holds — no bound is provable
  there.) Census-branch order: fib-audit compare (+revoke on
  mismatch/error) → `pollIpsecTopology`; no cadence gate needed
  (structural 1Hz + ~10ms select jitter). Each tick runs (a) RPDB:
  `ruleListFn` both families + inventory tuple-match, and (b) FIB: RAW
  `RouteListFiltered` dump over `LearnedRouteTableIDs` for q0-path tables
  — NOT `importableRouteScoped`, whose refusals (non-unicast, off-allowlist
  incl `RTPROT_REDIRECT`, gateway-less connected, ECMP-half, unscoped
  link-local, `:249-330`) would blind the detector to real main-254 shapes
  (blackhole covering a permitted dst, redirect host route, new connected
  prefix) — with normalization (nil-Dst→canonical CIDR,
  LinkIndex→name-or-drop-when-global, drop Src/metrics/encap, sort multipath
  legs, string-normalize IPs), compared against the ROUTE BASELINE. Baseline
  store is a new `RouteBaselineStore` in pkg/routing (sibling to the
  importer): `tables map[int][32]byte` + per-table per-route digest sets,
  `Capture`/`Compare`/`Commit`, owned by `routing.Manager` (`New`,
  `routing.go:69`), exposed as `Manager.RouteBaseline()`; updated at
  admission (`applyPolicyRoutingRules` success +
  `reconcileRouteLeakSnapshot` publish, `daemon_apply.go:578-593`, BOTH
  succeed else #9693 debt) and authorized-change commit (`#9693`
  reassert success + `actuateLearnedRouteRefresh` republish); compared
  read-only in the audit (per-table digest equality; mismatch →
  set-diff attribution → fail-closed debt + metric, never auto-adopt).
  Table-999 stays excluded by design (double-excluded importer set;
  never consulted for q0 — and any rule steering q0 lookups INTO 999 is
  itself an intersecting rule the RPDB leg catches). P-MECH admission
  REQUIRES `EnableLearnedRouteImport` on. Mismatch OR poll error on
  EITHER leg → SYNCHRONOUS deny in-tick (poll failure is fail-closed,
  never skip). For out-of-model external writers, RPDB mutation takes effect
  before notification: worst case ≤1s + dump + revoke before denial, which
  admits up to ≤1s of NEW q0 writes under the changed environment PLUS the
  in-flight cap at detection (both quantities are asserted; not in-flight
  alone). CASE COMPOSITION: healthy-census detection is ≤1s + dump +
  revoke, while a stall-start write is exposed until independent
  watchdog-fire at ~3s + revoke; both bounds include the in-flight set at
  detection; §7 requires recording the stalled packet window. `RuleSubscribe`
  reduces normal event latency to callback+revoke,
  not zero pre-effective exposure; dropped rule events are covered by the
  1s census audit. FIB route events similarly deny at callback+revoke; a
  dropped edge is bounded by the 1s periodic raw-FIB re-read. These external
  paths are detection-bounded only and do not satisfy the owned-mutation
  zero-observation invariant. Netlink dumps are bounded, inventory reads
  use short mutexes, and revoke is CAS-only nonblocking. SUPERVISOR-STALL
  WATCHDOG (v14 Sec B6): a separate, nonblocking liveness monitor reads an
  atomic `lastAuditService`; if age exceeds 3s (two missed census intervals
  plus jitter), it forces deny-only and alarms without acquiring audit or
  apply locks. It is not serviced by the census goroutine it supervises.
  INSTALL INVENTORY (CYCLE FIX — v6 wrongly placed the owner type
  in userspace, which routing already imports via `routes.go:13`): new
  `InstallInventory` in pkg/routing, owned by `routing.Manager`,
  value-copy readers for daemon + supervisor audit (allowed direction);
  writers record directly (same package) + daemon-direct (allowed
  direction). CORRECTED writer record points: ruleOps impls
  (`rule_dscp_linux.go:58`, `rule_l3mdev_linux.go:20` —
  `pbr_applied_7422.go:70-71` REMOVED, it answers kernel counts via
  `RuleList`, a reader) + next-table Apply `:129`/clear `:473` + rib-group
  Apply `:572`/clear `:769` (three windows + return-1500) + return
  (`rib_group_return_9819.go:77`) + PBR Apply `:899`/clear `:1010`
  (band 31000-31999; clear has NO `isRuleAlreadyGone` filter — record
  raw dispositions) + probe_pin Apply `:176`/clear `:270` (rules band +
  all-50-table route flush) + VRF-term install/remove
  (`vrf_miss_terminator_9819.go:58`, from `Create`/`Reconcile`/
  `ReassertMissTerminator`/empty/retry) + commit tail
  (`applyPolicyRoutingRules` `:286` via `applyRoutingRules` `:252` via
  `applyConfigLocked` `:578`; FRR structurally separate) — apply AND
  clear BOTH recorded, post-normalization disposition
  (`isRuleAlreadyGone` `:519` / `isRuleAlreadyPresent` `:527`).
  Revoke is DIRECT `s.revokeTransitPermitNonblocking` (nil-safe; no
  injected callback exists because no cross-package seam exists in this
  direction). Sequence is CHOSEN explicit
  `allocCloseEventSeqAfter(old.closeRequestSeq)` (Seq0 reserved for
  `holdIpsecHostInputFenceForDivertTransition` only). Episode
  stability: the audit records the last-revoked key; same key as the
  current permit `closeRequestKey` + already CLOSING → SKIP revoke (no
  call); new revoke only on OPEN state or key change — no per-tick seq
  churn. Tuples: `Kind:"fib-audit"`, `Owner:"audit"` (never `kernel`),
  `Name:"rpdb:<band>:<prio>"` / `"fib:<table>:<dst>"`,
  `Ifindex:0`, `MasterIndex:0`, `Ready=UNKNOWN`; generation reads
  `s.watch.Load().Generation` (nil→0) cross-checked against
  `permit.watchGeneration`, bound `(gen, seq, epoch)` — no new accessor and
  no per-tick sequence advance.
  The async `routeListener` is a FIB-change observer: an unexpected
  external mutation triggers synchronous deny/revoke at callback time,
  while owned changes still rendezvous before effective mutation. The
  listener cannot prevent external installation; dropped edges remain
  bounded by the periodic raw-FIB re-read in (4).
  (5) FRR/ZEBRA KERNEL-FIB MUTATION AUTHORITY — SINGLE NORMATIVE POLICY
  (v14 Opus R1; replaces every competing route-map/permit interpretation):
  admitted q0-path tables contain only routes whose mutation owner is xpfd
  and whose effective-change boundary is serialized by S4. `routing.Manager`
  and the daemon's explicitly inventoried route writer own xpfd static
  route `RouteReplace`/`RouteDel`; the pre-effective boundary is the
  S4 close → `FenceAuthorityAck` with zero old-epoch queued/started/
  unreleased I/O → netlink mutation → fresh predicate/admission → OPEN.
  Kernel `connected`/`local` entries are admitted ONLY when they are
  synchronous consequences of an xpfd-owned link/address operation in that
  same closed transaction; any carrier/autoconf/address action whose route
  effect cannot rendezvous BEFORE the kernel change disqualifies the table.
  FRR/zebra protocol routes (connected/static/kernel/BGP/OSPF/OSPF6/RIP/
  RIPng/IS-IS and any other FRR-supported install protocol) have NO
  mutation authority over an admitted q0-path table: `buildManagedSection`
  and `ApplyFull` refuse any table/VRF/attachment/redistribution that
  offers such a path, and admission readback verifies both managed config
  and running protocol attachments. An unrecognized protocol, unmanaged
  zebra config, external static writer, kernel/autoconf writer, or route
  whose complete writer set/pre-effective boundary is not proved causes
  admission refusal (deny-only). The supported-configuration restriction
  is owner-reviewed before P2 (`M1_SUPPORTED_CONFIG_APPROVED`); it forbids
  DHCP/networkd/operator and any other asynchronous writer intersecting
  q0 rules/tables while OPEN. There is no “configured protocol” permit and
  no FRR route-map is credited as serializing a later replacement or
  withdrawal.
  The OWNED-mutation decision is uniform: while OPEN, xpfd refuses every
  intersecting rule, route, nexthop, connected/local-route source, or
  receive-mode change before effective mutation. An authorized xpfd-owned
  change first closes through S4 and waits for old-epoch fence ACK /
  `IoRelease` drain; only then may its writer mutate. Out-of-model external
  writers are not refused pre-effect; detection is bounded only as in (4).
  No observer, route event, `BumpFIBGeneration`, revoke-after-install, or
  R/A/K sample is pre-install exclusion.
  R/A/K remains an admission/convergence audit only: R is the managed
  config readback; A is the running FRR protocol/attachment readback; K
  is the kernel-FIB inventory. All three must agree before OPEN, but a
  post-install sample never authorizes a preceding asynchronous write.
  FRR's `show route-map` reports definitions, not install attachments;
  read both definitions and `show ip/ipv6 protocol` attachments and
  reject any q0-table install path, foreign permit, unknown attachment,
  or unmanaged remainder. Every `ApplyFull`/`Clear`/reload/retry and
  periodic routing-reconcile hook uses this same refusal/readback
  contract; lifecycle mutation goes through the pre-effective S4
  rendezvous, not a watcher.
  R1 ACCEPTANCE CELL (deterministic, pre-P2): admit a q0 route, pause an
  old write after authorization, then attempt zebra replacement AND
  withdrawal/nexthop replacement for that same route. The test must show
  either (a) zebra is rejected at admission and the FIB remains byte/
  semantically unchanged while the writer is paused, or (b) if an owner-
  reviewed zebra rendezvous is ever added, the FIB change is not effective
  until old `FenceAuthorityAck` with zero `io_unreleased`/residual. A
  post-install revoke, event, or R/A/K convergence cannot pass this cell.
  Include clean valid FRR attachment as control; unmanaged zebra config,
  missing attachment, or unknown protocol all refuse before OPEN.
  (6) REFUSED RULE SET, SEMANTIC: a rule INTERSECTS q0 iff its selector is
  not provably disjoint from q0 traffic; disjoint requires iif-pinned-to-
  non-q0 OR mark-disjoint (mask pins bits q0 never sets); DEFAULT IS
  INTERSECT. This explicitly includes the destination-only rib-group leak
  (`Dst/Table/Priority/Family`, no Iif/mark; `rules.go:674-684`), which
  matches by Dst alone. While OPEN, xpfd refuses any intersecting rule
  add/delete, any q0-table route/nexthop/source mutation, and any usp0/usp1
  receive-mode change BEFORE effective change. An out-of-model external
  writer is not “fenced around”: it triggers immediate deny/revoke and the
  bounded detect-then-revoke exposure in (4); this is not credited as
  pre-effective exclusion or as preserving the zero-observation invariant.
- M1 mutation linearization (owned end-to-end by the S4
  `ipsecSupervisor`): (1) STOP ADMISSION: `revokeTransitPermitNonblocking`
  → CLOSING + `permitEpoch`++ (`ipsec_reinject_supervisor.go:260-302`)
  PLUS a `FenceAuthorityClose{run_id, generation, permit_epoch,
  fence_seq}` request on the submit socket: `MSG_FENCE_CLOSE = 4`
  (1,2,3,11,12 taken, `slowpath_reinject_9506.rs:36-40`); Go encoder
  `encodeFenceClose` (beside `encodeCancel` `:394` / `encodeAnnounce`
  `:309`), Rust decoder `decode_fence_close` (beside `decode_cancel` /
  `decode_announce`), Go send-site `SendFenceClose(close
  FenceAuthorityClose) (FenceAuthorityAck, error)` on
  `SocketReinjectSubmitter` — new 4th method on the `ReinjectSubmitter`
  interface (`pipeline.go:117-121`), implemented on the socket client
  (+ inherited by `ipsecReinjectSubmitter` via embedding). LOCK SCOPE
  (CHOSEN): hold `submitMu` across the FULL round-trip — encode
  outside, then lock + ensure + write + ack-wait + unlock
  (`SubmitAdjudicated` `:125-134` shape, NOT `CancelReinject` send-only:
  releasing before the read would let a concurrent `SubmitAdjudicated`
  interleave `Admit` vs `FenceAck` on the single submit conn mid-fence);
  the hold is bounded by the existing `s.timeout` 5ms read deadline
  (`:85`, `:228`) + write time, timeout → fail closed (no ack, no
  mutation). S4 HANDLE (named — the supervisor holds no submitter
  today, `:174-203`): new `fenceSubmitter` field on `ipsecSupervisor` +
  `SetFenceSubmitter` setter called from capture wiring with the LIVE
  runtime selection (`pending?staged:active`, `:511-517`/`:545-550`,
  evaluated at fence time, not stage time); the new S4 `fenceAuthority`
  method (`ipsec_reinject_supervisor.go`) sends Close through that
  handle and awaits the ack. THE
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
  AND NO unreleased I/O (`IoRelease`) AND NO `Leaked` row under the old
  epoch. LOCK SCOPE (SOLE AUTHORITY — R9-SEC-01: the (c)/(e) three-lock
  hold is the ONE fence-scan scope; any single-lock reading of this
  paragraph is SUPERSEDED): scan AND rescan each hold
  `core.inner → journal.records → obligation-store` SIMULTANEOUSLY
  (the (c) order, `try_lock` on 2nd+3rd, contention → abort phase →
  NO ack, fail-closed) — a scan under `core.inner` alone would land
  between another path's core-terminalize and its obligation insert
  and ack spuriously; under the shared hold the scan sees every
  handoff commit atomically (pre-commit `WriteStarted` BLOCKS the
  ack; post-commit `Terminal`+`Leaked` FAILS it — never a false
  ack). TWO-PHASE (authority-close FIRST — step (2) — so no new
  `Proceed` can start; the resolve leg runs BETWEEN the holds
  because `resolve_write` needs the locks and cannot run under
  them): hold → scan → release → fence-drive `resolve_write` for
  `Proceed`-before-scan entries (bounded by the 5ms ack deadline,
  timeout → no ack + alarm) → hold → rescan → ack. A `Proceed`
  winning the race before the scan must resolve before the ack
  completes; a `Proceed` after sees closed authority and `Fenced`;
  a handoff commit landing between the holds is ATOMIC, so the
  rescan sees it whole (`Terminal`+`Leaked` → ack still FAILS,
  epoch permanently fenced — §7 cell (ii)). Purges are forbidden
  in the fence window (they surface no completion) or counted
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
  MODE — SELECTED, no alternatives. OWNED-MUTATION INVARIANT (v14 B1):
  from the first old-epoch submission through the last possible routing
  decision, including CLOSED, every xpfd-owned RPDB/FIB/receive-mode
  mutation waits until all old-epoch I/O is final (`IoRelease`-proved
  drain + `FenceAuthorityAck` with `io_unreleased==0` and
  `residual_old_epoch==0`). Under enforced receive mode, each old skb's
  routing decision completes before its write's I/O finality; therefore
  no old skb can observe the environment changed by an authorized xpfd
  mutation. This is NOT a zero-observation guarantee against an external
  writer: an out-of-model RPDB write can expose up to ≤1s of NEW q0
  submissions before periodic detection plus the in-flight cap at
  detection, with rule-event callback/revoke normally faster; FIB's
  dropped-event bound is one audit interval. Those exposures are
  detection-bounded (§4), counted by P2 cells, and do not earn pre-install
  exclusion credit. The CLOSED interval is covered for owned mutation
  because I/O finality precedes its effective boundary. ENFORCED RECEIVE
  MODE on usp0/usp1 (new enforcement):
  `IFF_NAPI` (already true — zero `IFF_NAPI`/`TUNSETNAPI` hits); RPS cpus
  EMPTY on all q0 queues AND RFS EXCLUDED — per-queue `rps_flow_cnt==0`
  with no flow table (RPS-empty alone does NOT disable RFS: the
  `rps_flow_table`/socket-flow branch in `get_rps_cpu` can select a
  backlog CPU with a NULL RPS map, and `rps_sock_flow_entries=32768` is
  already set globally by `compiler.go:1841`); GRO OFF; NO XDP program
  attached; TC classifier pinned (existing mark); `rx_batched == 0`
  (see B8 below — member `tun_rx_batched` holds skbs iff
  `rx_batched>0 AND more`; belt over the structural `!more` proof);
  kernel version PINNED to the allowlist below. STRUCTURAL `!more`
  PROOF (B8, member-text + repo-shape): xpf USP TUNs are created
  `IFF_TUN|IFF_NO_PI` without `IFF_NAPI`/`IFF_VNET_HDR`
  (`slowpath.rs:2220,2240`); ALL USP writes are char-fd `write`
  (`slowpath.rs:1750`) or uring `OP_Write`
  (`io_uring_write.rs:583`) → member `tun_chr_write_iter`
  (hardcodes `more=false`, `tun.c:1985-2000`); the ONLY `more=true`
  source is `tun_sendmsg` via `MSG_MORE` (`tun.c:2512-2561`),
  unreachable — `sendmsg` on the USP char fd fails `ENOTSOCK`
  (errno 88, EXECUTED probe, record §7), so a sendmsg mutant
  fails LOUDLY, never holds silently. Queue-empty induction:
  entries enter the batch queue ONLY via the more-path
  (`:1496-1498`) or the NAPI path (`:1936`, napi off) — under
  all-`!more` writes from a fresh TUN the queue is always empty,
  so `(!more && empty)` dispatches inline on EVERY write
  regardless of `rx_batched`. READBACKS (every field, every
  tick): glob
  `/sys/class/net/xpf-usp{0,1}/queues/rx-*/{rps_cpus,rps_flow_cnt}`
  (`compiler.go:1842` glob pattern; empty dir set or any nonzero → refuse)
  via `os.ReadFile` (`process.go:465-490` pattern); ethtool GRO line
  (`compiler_rxvlan_classify_9946.go:58-65` parse) + ethtool
  coalesce `rx_max_coalesced_frames == 0` (same channel/cadence;
  nonzero → refuse + drift path); phydev-absent (no
  `/sys/class/net/xpf-usp{0,1}/phydev` — belt over the member-text
  proof that TUN never takes `skb_defer_rx_timestamp`; present →
  refuse + drift path); XDP via netlink
  `Info().XDP()` (`armproof.go:849-860`, modes `:786-802`); TC via `tc
  filter show` / netlink TC dump (clsact prio `0x7fff`); `uname -r` +
  manifest `guest_kernel` + allowlist match. KERNEL ALLOWLIST
  (PINNED TUPLE, not self-consistent metadata): the member is the tuple
  (§0 of the record): uname `7.0.0-30-generic` + base digest
  `9dc7c536…e21be05` + package rows (`linux-{image,modules,headers}-`
  `7.0.0-30-generic == 7.0.0-30.30`, SHAs §1) + source `linux
  7.0.0-30.30` (tag `Ubuntu-7.0.0-30.30` @ `d974a4063`) + Kconfig
  (`CONFIG_4KSTACKS` absent-or-`n`, `CONFIG_BRIDGE` +
  `CONFIG_NF_TABLES_BRIDGE` set) — pinned in repo (Python beside
  `PINNED_BASE_*` in `bake.py`, Go consts beside the LANE-1/validate
  call sites, agreement test asserting the identical tuple,
  `mixed_version_matrix` precedent) — updated ONLY by reviewed
  commit alongside a new review record. The F0 recording is
  CONFIRMATION (bake rows must EQUAL these pins), never blank
  REVIEW RECORD (COMPLETED v14):
  `docs/pr/9506-delta/kernel-allowlist-7.0.0-30.md` — instantiated tuple +
  source/tree identity + SHA-verified deb capture + member config capture +
  per-branch MEMBER-TEXT review (B1–B8 at pinned tag, file:line quoted) +
  per-boundary MEMBERSHIP recipes (`f0f9-recipes.md`, full recipe matrix) +
  executed-evidence transcript (§7) + artifact ledger (§8) + explicit
  limits. `kernel-source-revision` canonical form (record §2): sorted
  comma-joined `pkg=ver` of the three kernel packages; `kernel-allowlist`
  is the member uname, EQUALITY-compared.
  BINDING (v14 full-tuple/full-matrix): each boundary consumes and compares
  every observable field vs repo pins; every LANDED boundary test must run
  the entire recipe matrix and repo-level LANDED `pins_consistency`
  agreement test (separate from the recipe-only helper; compare `bake.py`
  pins, Go constants, and recipe pin tuple). Recipe scripts
  are behavioral truth tables, not byte-identical implementation. B8
  member-kernel probes are SPECIFIED/NOT EXECUTED. Same-version/different-
  binary runtime kernel integrity is explicitly OUT OF MODEL (allowlist
  §6); no runtime same-bits claim is made. Current-code gap demonstrations
  and specified verdicts follow: `bake.py` asserts `ls /lib/modules` equals
  exactly the member AND all three installed
  `linux-{image,modules,headers}-7.0.0-30-generic` dpkg rows equal
  `7.0.0-30.30` (new run-commands beside `:645-646` / `:670-671` /
  `:676` + hold-verify `:708-721` shape — current: installs newest
  `linux-generic`, `:641`); `sign.py` `assert_bake_set` (extends
  `:438-442`) requires `guest_kernel`==pin AND
  `kernel-allowlist`==pin (EQUALITY, never truthiness) AND
  `kernel-source-revision` parsed per §2 grammar with all three
  rows==pins AND `validated`/`base_image_pinned`/`base_image_sha256`
  ==pins (current: nonempty `guest_kernel` only — SIGNS `-31`,
  demonstrated); `publish.py` `gate_provenance` requires manifest
  AND inventory EACH vs PIN (both `guest_kernel`==pin, manifest
  `kernel-source-revision` parsed per §2 grammar + inventory row
  sets image+modules+headers==pins, `kernel-allowlist`==pin, base
  pins, `xpf`==ver; current: manifest↔inventory agreement only —
  PUBLISHES coherent `-31`, demonstrated; cross-agreement retained
  as tamper-evidence); `validate.py` scenario A (`:1185-1230`)
  asserts `uname -r`==pin + single module dir==pin + all three
  guest `dpkg-query` rows==pins + Kconfig third predicate live
  (current: floor only — PASSES `-31`, demonstrated); LANE-1 Arm
  compares the FULL candidate tuple (candidate uname + 3 rows from
  the candidate inventory vs pins) after `ValidateKernelSegment`
  (new check — the function itself is charset/path validation,
  `version.go:124`); Gate 2 (`kernel_run.go:551-558`) compares
  running uname + running dpkg rows + RUNNING Kconfig
  (`/boot/config-$(uname -r)`) vs candidate rows vs pins —
  checked in `verifyAndPromote`, shared by normal and BootCurrent-
  unreadable recovery entry (`kernel_run.go:524-531`). Separate LANDED
  wiring cell injects unreadable BootCurrent with running==candidate and
  non-member live Kconfig (e.g. `CONFIG_4KSTACKS=y`); shared gate must
  REVERT without calling promote. Also exercise a bad running package tuple.
  The truth-table
  recipe alone cannot pass this cell. Current `running==CandidateVersion`
  strings only promote unreviewed `-31` (gap by code read);
  `xpf-kernel-promote` outer gate refuses no-infer (current:
  authenticates the xpfd binary path,
  `kernel_arm_record.go:39` — gap by code read) AND non-member;
  `promotionMarkerPath`/`lastRollPath`/`ReadChannelStatus`
  (`kernel_status.go:84` — REPORTING, not enforcement) become
  EVIDENCE INPUTS to the membership check; ordinary-boot
  admission asserts booted uname + 3 dpkg rows + live Kconfig AND
  manifest uname + revision-rows + allowlist, ALL vs pins, before
  OPEN (booted
  non-member runs the system but never opens permits); rollback
  to a non-member known-good proceeds as a system function but
  P-MECH admission refuses OPEN until a member kernel runs
  again. Floor unchanged (>=6.18, `-generic` flavor,
  single-kernel invariant, mlx5 set); any kernel not on the
  list → deny until reviewed and listed via reviewed commit
  (same shape as `PINNED_BASE_RELEASE` bumps).
  MEMBER-BACKED SEMANTICS (tag `Ubuntu-7.0.0-30.30`, record §4 B7):
  v4 `tun_get_user → netif_receive_skb →` (RPS map NULL AND no flow
  table → `get_rps_cpu` -1, `dev.c:5131` → `__netif_receive_skb`
  inline, `:6372-6394`) `→ ip_rcv → ip_forward`
  (`ip_input.c:564 → :439 → ip_forward.c:83`); v6 `ipv6_rcv
  → ip6_forward` (`ip6_input.c:304 → :69 → ip6_output.c:497`,
  same inline shape — NOTE the 7.x `ipv6_rcv` rename, NOT
  `ip6_rcv`). RPS/RFS/NAPI/GRO reasoning is L2
  (family-independent), the TC mark program is family-blind
  (mark/`queue_mapping` only, `slowpath.rs:188-263`), and TUN
  `IFF_NO_PI` parses family by nibble (`gre.rs:710-714`); route
  lookup completes synchronously within the `write()` syscall, so
  target-CQE/write-return proves the routing decision already
  happened under the then-current env (modulo the B8 kprobe
  timing bar at P2 entry). HOLD (not sampled-at-OPEN): in-process
  mode changes on usp* are refused while old q0 I/O can route (tuner
  already phys-only + explicit usp exclusion); the (4) audit re-verifies
  FULL predicate every tick. DRIFT IS NEVER INSTANTLY SAFE: mode
  drift → synchronous revoke + fence; epochs finalized after the last
  GOOD readback are marked ASYNC-SUSPECT until the S4 fence proves all
  old-epoch I/O final. That proof permits same-environment OPEN only
  after the remaining S4 checks pass; step-6 mutation remains prohibited
  by a boot-bound PERMUTATION-FREEZE until reboot (persisted flag, new
  `/var/lib/xpf/pmech-permutation-freeze` beside the kernel-promoted
  state — reboot is the designated retirement boundary for
  untrackable downstream skbs). FLAG DISCIPLINE (R9 P1-freeze —
  BOOT-BOUND SELF-CLEARING, the named agent is the supervisor
  itself on read — no external clearer exists or is needed):
  content = `{boot_id, entries[{kind, gen/epoch?, reason, at}]}`;
  kinds: `crash-unclean` (written by case-(4) crash),
  `mode-drift` (written by drift fence), `helper-unclean`
  (written by helper-handoff, (g)). LOCKING (Hostile-4 — one
  lock, all mutating paths): the flag flock (`withEpochFileLock`
  on the flag path) covers read-modify-write AND stale-read
  unlink AND case-(2) hygiene unlink — all three take the SAME
  lock, singly held, NEVER nested with the authority flock
  (case-(2) orders: authority rewrite → release → flag hygiene).
  Every read compares `flag.boot` vs current boot FIRST: stale
  boot → take the flag flock → RE-READ boot inside the hold →
  unlink ONLY if still stale (a concurrent RESET write that won
  first leaves current-boot entries the unlink must NOT delete —
  this check-then-unlink-under-one-hold closes the
  stale-unlink-vs-RESET race) → treat as CLEAR (post-reboot
  mutation allowed again after fresh-init + re-admission — no
  re-freeze, no forever-refused mutation; the locked unlink is
  RETRIED on every stale read until it succeeds — best-effort,
  one locked syscall per read);
  current boot + non-empty entries → mutation REFUSED.
  Known stale-boot unlink failure → row 6: alarm; refuse mutation,
  but OPEN iff otherwise admissible (same-environment fresh admission,
  no unresolved ancestor). Non-ENOENT read error → row 5: treat as SET,
  REFUSE both OPEN and mutation, and alarm. WRITE SIDE
  (R9 Host-6/7 — cumulative appends are FORBIDDEN without a
  boot check): every flag write runs read-modify-write under
  the flag flock (same `withEpochFileLock` pattern as the
  authority file; NEVER hold both flocks simultaneously):
  absent/ENOENT → write `{current-boot, [new-entry]}`;
  file boot STALE (≠ current) → RESET to `{current-boot,
  [new-entry]}`, DROPPING stale entries (a read-modify-append
  lane recording a current-boot freeze under a stale boot_id
  would self-clear on next read — legitimate freeze silently
  evaporates; the reset closes exactly this); file boot
  current → append. Malformed file → treat as SET + writes
  OVERWRITE with `{current-boot, [new-entry]}` (fail-closed
  preserved: the new entry keeps it SET). WRITE FAILURE →
  live-freeze-until-reboot + alarm (SAME as authority
  nil-persist-fail: revoke if OPEN + bar OPEN + bar mutation —
  never silent-allow step-6 with untrackable skbs). DAEMON
  IN-MEMORY MIRROR (the write-failure backstop survives helper
  restart): the daemon holds `fenceFlagLive` (sticky SET on
  any write failure, cleared ONLY by reboot-init); the
  OPEN consults `fenceFlagLive` as a sticky persistence-failure mirror;
  if the mirror is SET, OPEN is false. A current-boot file entry with the
  mirror CLEAR is instead a durable mutation-only freeze (decision table
  below); daemon restart re-reads the file and reinitializes the mirror.
  HYGIENE-UNLINK under the SAME flag flock
  with the same re-read-if-stale guard (case-(2) belt; never
  unlinks a file a concurrent RESET already made current).
  HYGIENE-UNLINK FAILURE: alarm + flag treated as SET for
  mutation (fail-closed) while OPEN proceeds iff otherwise
  admissible (same-env reopen; mutation refused until a later
  stale-read unlink succeeds). Same-env reopen is allowed after full
  re-admission (fresh predicate PASS incl. mode) + zero
  old-epoch I/O outstanding, but routing-env mutation stays
  refused while boot-current entries exist.
  ENFORCEMENT: admission verifies every predicate field; change attempts
  while OPEN are refused before effective change. S4 OPEN-VS-MUTATION
  DECISION TABLE (v14 Host P1 base; v15 closes the row-4 and read-routing
  residuals; sole authority for this subsection, recovery section (g), M1
  and §7 — replace any prose-level rule that disagrees):

  | State at `tryOpenPermit` | OPEN | Routing/FIB mutation |
  |---|---|---|
  | Current-boot flag absent/clear; mirror clear; no unresolved ancestor; fresh predicate/mode/authority/worker/ledger checks pass | Allowed for this generation | Only by S4 close → fence ACK + zero old I/O → owned mutation → fresh admission |
  | Current-boot durable flag set; mirror clear; same effective routing/mode environment re-proved; zero old I/O and no unresolved ancestor | Allowed after same-environment re-admission (same or fresh generation); the flag does not itself block OPEN | REFUSED until reboot retires the flag |
  | `fenceFlagLive` sticky mirror SET, regardless of file contents or fresh predicate | REFUSED until reboot-init clears the mirror | REFUSED until reboot |
  | Unresolved `Leaked` ancestor, regardless of descendant generation or clean snapshot | REFUSED until reboot retires the boot-bound epoch | REFUSED until reboot retires the boot-bound epoch |
  | Unreleased `IoRelease` ancestor | REFUSED until target-write release or bound-writer death-proof; then re-evaluate all remaining S4 OPEN checks | REFUSED while unproved; after proof, only the ordinary S4 close → fence ACK + zero old I/O → owned mutation → fresh admission sequence |
  | Drift `ASYNC-SUSPECT` ancestor | REFUSED until the S4 fence proves all old-epoch I/O final; then same-environment fresh admission only, subject to the remaining rows | REFUSED while the boot-current PERMUTATION-FREEZE is set, including after fence finality; reboot is required |
  | Malformed/unreadable current file or non-ENOENT read error | REFUSED + alarm | REFUSED + alarm |
  | Known stale-boot file whose unlink failed; mirror clear; no unresolved ancestor | OPEN only if same-environment fresh admission passes | REFUSED + alarm until a locked stale-read unlink succeeds |

  A new helper incarnation may be announced and staged, but its promise of
  “new-generation admission” is conditional on the table: it MUST NOT OPEN
  while any inherited ancestor obligation is unresolved. A clean helper handoff
  with no outstanding ancestor may re-admit under a fresh generation while the
  durable freeze still prohibits mutation. Sticky mirror SET is not that case.
  Same-environment recovery never licenses mutation. The refused set while
  OPEN includes every q0-intersecting RPDB add/delete, q0-table route/nexthop
  or connected/local source change, and usp0/usp1 receive-mode change.
  Enforcement points: ruleOps choke + facade/apply-boundary refusal +
  FIB-ingest refusal + receive-mode refusal (`tuneInterfaceBuffers`
  name-guarded off usp*); the out-of-process residual is bounded only by
  the detected-writer policy in §(4), not by these owned-writer guards.
  Never count TUN return length, consumed completion, closed ring, or
  `delivered` counters as downstream quiescence. (RPS-on-q0 was NOT FOUND
  today — `compiler.go:1840-1857` tunes XDP physical NICs only — v5 ADDS
  the enforcement rather than depending on current state.) (6) MUTATE under
  the single writer, re-snapshot live rules/routes, re-evaluate the predicate,
  and reopen only if the authoritative table permits it. CHECKS (benign, all required):
  CHECK — writer paused after `pre_write_check` but before the TUN call
  → mutation MUST NOT become effective; FIRST-CHECK-DEADLINE VARIANT —
  expire the ack deadline in the same pre-park pause → ownership-only
  transfer per (a) (no terminalization), fence BLOCKS (no ack),
  deny-all + `STUCK_WRITER_CLOSED` + alarm, CLOSED on late coordinated
  resolve or death-proof to `Leaked`; DEFERRED-I/O CHECK — op held
  unresolved in the ring after terminal-`Uncertain` is acked → the M1
  ack MUST fail; DOWNSTREAM-LIFETIME CHECK — mode cells
  (RPS-empty/RFS-excluded/GRO-off/no-XDP/TC-pinned/rx_batched-zero/
  kernel-allowlisted enforced + drift→revoke+fence+freeze) PLUS
  mutation attempted with unreleased I/O → prohibited (a
  terminal-CQE-complete skb pending downstream is IMPOSSIBLE under
  the enforced mode because its routing already decided — asserted
  by member-text mode proof (record §4) + the B8 kprobe timing bar,
  not counters); RFS FIXTURE — all listed mode fields safe +
  `rps_flow_cnt!=0`/table present → admission MUST refuse;
  RX_BATCHED FIXTURE — ethtool-set `rx_max_coalesced_frames=64`
  while OPEN → revoke+fence+freeze (drift path — the structural
  `!more` proof makes this belt, tested anyway); SENDMSG-MUTANT —
  route USP writes through sendmsg → must fail loud `ENOTSOCK`,
  never silent success (red-team; base probe EXECUTED, record
  §7); KPROBE SYNC-PROOF (P2 on the member kernel — the timing
  bar no code read can give): `ip_forward`/`ip6_forward`
  entry+exit strictly inside the `tun_chr_write_iter` window for
  xpf-shape writes, both families; PTP NO-DEFER CELL (P2 on the
  member kernel — B7-ts adversarial): PTP-class inner frames both
  families route inline (no `skb_defer_rx_timestamp` stall — phydev
  NULL) + no `/sys/class/net/xpf-usp*/phydev` readback;
  MISSING-QUEUE FIXTURE — empty rx-* dir set → refuse;
  ALLOWLIST-EVIDENCE FIXTURES — completed v11 record +
  tuple-MEMBERSHIP reject at EVERY boundary
  (bake/sign/publish/validate/LANE-1/arm + ordinary-boot +
  rollback, F0–F9 incl F0 pin-confirmation, F5b booted-non-member,
  F5c rollback-non-member; coherent-B `-31` + revision-skew
  REJECTED at each — recipes RETAINED+EXECUTED (`f0f9-recipes.md`
  matrix ALL-HERE-OK + record §7–§8, LANDED gates at P2 entry) +
  per-branch member-text table
  (B1–B8 with file:line@tag) + honest F-statuses
  (RECIPE-EXECUTED, never LANDED pre-P2); DRIFT FIXTURE — inject
  mode drift → revoke + fence; ASYNC-SUSPECT blocks OPEN until the
  fence proves all old-epoch I/O final and clears ASYNC-SUSPECT; keep the
  boot-bound freeze mark present, then same-env OPEN is allowed only after
  fresh admission while mutation remains refused. Assert the freeze mark
  survives helper restart and is stale-unlinked only after boot change;
  require the post-reboot mutation-allowed-again cell.
- M2 egress oracle: before the first Permit is coded, approve a design that
  correlates each q0 submission to the actual selected egress table/domain and
  observes post-write disposition. The nft `delivered` witness is only a
  fence-mark match (`transit_barrier.go:17-22,276-280`), never this oracle.
  If table-254 egress cannot be distinguished from other routing domains, keep
  every production policy result advisory/deny-only and re-plan.
- M3 overlap/source admission — EXPLICIT CONTRACT AMENDMENT (v14 Opus R2;
  canonical route-derived provenance is NOT silently “held”). The canonical
  `ebcec7ad4:docs/pr/9506-xfrm-capture/pmech-design.md:411-448` contract
  requires `effective_prefixes = R_main ∩ explicit_remote_ts`, complete
  route/ECMP ownership, and `ingress_prefixes` as the direction-normalized
  copy. This amendment supersedes ONLY that source-provenance/derivation
  rule: source authorization becomes a narrowly authored per-tunnel
  allowlist. It does NOT supersede D_usp1/main-table route-domain checks,
  FIB-generation freshness, complete route/nexthop inventory for M1/M2,
  disjoint-tunnel admission, deny-on-missing-snapshot, or drain-then-
  effective revocation.
  OWNER APPROVAL IS A HARD GATE: `M3_AUTHORED_PREFIX_CONTRACT_APPROVED`
  defaults false and is flipped only by an explicit #9506 owner decision
  accepting this amendment and its migration burden. Before that evidence
  exists, P-MECH rows remain deny-only and no production Permit is
  authorized. The header's “credited designs held” statement is therefore
  narrowed: this provenance contract is an unapproved amendment, not a
  canonical-design closure.
  (1) SCHEMA/MIGRATION: add per-tunnel `ingress_prefixes` to `IPsecVPN`
  (`pkg/config/types_security.go:1973-1980`, covering `LocalID`/`RemoteID`/
  `BindInterface`) and its schema leaf. Existing configs lacking the field are
  valid ordinary configs but are NOT P-MECH-admitted: no synthesized
  prefix, route-derived backfill, wildcard default, or implicit open.
  Operators must explicitly author concrete prefixes and pass the owner
  approval gate; strict commits never auto-migrate existing configs.
  Tolerant boot/HA/peer-sync without the field keeps the tunnel row absent
  (deny-only), never warns-and-admits. Bind the field to
  `IpsecTunnelSnapshotGeneration`; row withdrawal or invalid prefix omits
  the tunnel row so exact D14 STN match denies.
  (2) AUTHORITATIVE SOURCE/DEFAULTS: the normalized authored list is the
  source-admission authority. Route-based implicit `0.0.0.0/0`/`::/0`
  traffic-selector defaults provide ZERO authorization. An authored
  `0/0` (either family) is ALWAYS rejected; no wildcard may enter the
  snapshot. An explicit non-wildcard remote traffic selector remains a
  ceiling: every authored prefix MUST be contained by at least one
  explicit remote selector or strict commit refuses; an authored narrower
  subset is valid. When remote selectors are implicit/default wildcard,
  only the concrete authored prefixes authorize. Local selectors remain
  identity/policy inputs, not a substitute source allowlist. Authored/
  selector disagreement is therefore deterministic: wider/out-of-selector
  authorship refuses/omits the row; narrower authorship narrows permission;
  packet sources outside the authored set DROP-and-count (E21 where a real
  tunnel overlap is implicated, otherwise the source-membership deny).
  (3) ROUTE OWNERSHIP ROLE (explicitly changed): xfrmi/route/nexthop
  ownership does NOT derive, widen, or intersect the authored source set.
  Complete route ownership remains a separate M1/M2 precondition for the
  packet's selected D_usp1/main-254 egress domain and FIB generation.
  Missing ownership or an absent route does not manufacture a source
  prefix: the source check may match the authored list, but the packet
  still fails route-domain/egress validation with E22/deny and cannot q0
  write. Partial/unresolved ECMP invalidates the complete M1/M2 route
  inventory and blocks P2 admission; no partial leg is dropped and no
  authored entry repairs that proof.
  (4) VALIDATION/PROVENANCE: strict commit CIDR-parses, canonicalizes,
  rejects empty/default/over-64-per-family lists, rejects authored-prefix
  overlap across admitted tunnels, and enforces the selector ceiling.
  Strict `CompileConfig`/`compileTreeStrict` rejects violations. Tolerant
  `Store.Load` and HA `Store.SyncApply` run the same semantic validator;
  invalid tunnel rows are omitted/quarantined to deny-only, never
  warn-and-admit. Re-anchor at tip `0ab1c7d87`: `IPsecVPN` fields
  `types_security.go:1973-1980`; strict compiler
  `configstore/store.go:619-628`; lenient compiler
  `configstore/store.go:822-845`; HA ingress `daemon_ha_sync.go:880-913`;
  commit/ancestry ingress `daemon_apply_commit.go:542`
  (`syncAndApplyWithAncestry`); boot `store_persist.go:79`. (5) TRANSPORT/PUBLISH: add sorted normalized
  v4/v6 CIDR vectors (max 64 each) to Go/Rust `IpsecTunnelRowSnapshot`,
  serde REQUIRED, bump exact snapshot version 35→36 and set
  `MinProtocolIngressPrefixes=36`; update fixtures, epoch/shape tests,
  and mixed-version matrix. Compose cross-feature floor as
  `max(MinProtocolIngressPrefixes, MinProtocolMultiZoneScopedPolicy,
  every other required snapshot-shape floor)`, not whichever feature
  happens to queue last. The commit preflight, reconnect/retry/reconcile,
  and final queue/socket-write check must carry this same composed floor
  with the generation/connection-bound peer authorization.
  Existing `tunnelRowsSnapshot` publisher binds every vector to the
  current `IpsecTunnelSnapshotGeneration`; create/update/recreate/zone
  move/refresh/withdraw all use the S4 close → cancel queued → drain
  started + `IoRelease` → `FenceAuthorityAck` → publish → effective
  sequence. No late revocation after `WriteStarted`.
  (6) EVERY-FRAME CHECK: extend the existing `d14_zone_gate`
  (`afxdp/ipsec_inner.rs:232`) in place, before policy evaluation and any
  session/NAT mutation. Commit/publish MUST obtain the old-prefix
  generation's acknowledged close before Arc-swap install. Rust scan
  retains the sole simultaneous `core.inner → journal.records →
  obligation-store` hold and two-phase rescan; `WriteStarted` remains
  visible through revalidate→TUN→resolve. Fresh-view
  `revalidate_permit_commit` compares D_usp1/main-254 route-domain,
  FIB/inventory generation, tunnel/if_id + authored prefix membership,
  zone/policy hash, and RuntimeView generation. (7) DISTINGUISHING CELLS
  (all fail-on-revert, before owner approval stays deny-only):
  authored `0/0` → strict refusal + lenient/HA row omission + zero q0;
  missing xfrmi/nexthop ownership with a matching authored source →
  source allowlist match does NOT create a route, E22/deny, zero q0;
  partial ECMP inventory → M1/M2 completeness refusal before P2 (not a
  successful authored-prefix admission); valid existing config with no
  `ingress_prefixes` → ordinary config remains loadable but no P-MECH
  row/OPEN (manual migration required); authored list wider than explicit
  remote selector → refuse/omit, while a narrower authored subset allows
  only its members; overlapping authored sets → commit refusal and runtime
  E21 DROP-and-count. Also retain rotation cells: pause a final
  `WriteStarted` after revalidation, attempt withdrawal → publish waits
  for ACK; write completes only while old prefix remains effective, then
  drain/publish/revocation; deadline with stuck writer stays CLOSED +
  alarm until resolve/death proof. Until owner approval AND all (1)–(6)
  land, P2 stays deny-only.
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

### V1a/V1b/V2 — VOID→PASS flips (V1a prerequisite order per Host P2)

- V1a structural attestation (no permit dependency) is scheduled BEFORE
  any P1/P2 live-entry proof: counters DONE (`1838aaf59` + Go decode +
  Prometheus — verify in-flip); remaining exact observers are
  harness-owned (dynamic fence-set, per-rule provenance/PF-bind,
  same-priority-chain absence, VRF transition, workload latency;
  `test/incus/*`, zero product overlap). The prerequisite requires
  source-bound manifests and running-process hashes for BOTH `xpfd` and
  `userspace-dp` on BOTH firewalls plus kernel/classifier identity;
  any missing, stale, or mismatched userspace-dp artifact rejects V1a
  and marks every dependent P1/P2 live result VOID before it can report
  PASS. T12 structural cells flip VOID→MATCH with archive-verbatim
  ATTEST/RESTORE/SUMMARY.
- V1b consumer flips are permit-dependent and remain AFTER P2; G2
  consumer cells stay VOID until P2 gates pass. V2 follows entry gates
  and permit implementation: packet-correlated one-q0-write/original-
  DROP proof; per-shape stage rates, measured B>=3 economics, memory
  accounting (skbs→verdict queues→TUN), throughput/fairness, and HA.
  Teardown-from-source, SA-gated outer/inner, fragment, MTU and IPv6
  parity remain P2-entry gates, not V2 afterthoughts.

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
- R4 — Wire-floor composition: config-snapshot protocol and HA session-sync
  tags remain separate contracts. P1 keeps its length-gated identity floor;
  M3's v36 ingress-prefix floor composes with `MinProtocolMultiZoneScopedPolicy`
  and every other required shape floor by taking the maximum. Commit and
  commit-confirmed preflight, reconnect/retry reconciliation, and final
  queue/socket write all bind the same selected peer capability and
  connection epoch; no single unrelated protocol bump substitutes for a
  per-feature floor.
- R5 — M1/M2 kill polarity: no production Permit code until the owner-approved
  supported-writer restriction, exact per-table/per-protocol mutation
  authority, pre-effective S4 rendezvous for every admitted owned route,
  RuleSubscribe + bounded external-writer detection, and M2 egress-oracle
  design pass. Out-of-model writes are detection-bounded, not prevented;
  any configuration requiring zero observation against such writers is
  refused/re-planned. Any invalid M1 predicate remains deny-only; absent M2
  proof means re-plan, not mid-P2 permit testing.
- R6 — D12a boundary creep: stateful INPUT misses stay E37; before P2 lands,
  the issue owner must record sign-off that stateful INPUT is outside #9506
  closure scope. No sign-off means P2 cannot be declared issue-closing; any
  later Option B claim still needs two-resource prepare/finalize proof.
- R7 — Single-writer/limiter coupling: prove the shared `tx_delegated` outlet
  and limiter split before enabling Permit. If that proof fails, implement the
  bounded queue split and re-run the entry gate; never expose a second writer.
- R8 — Live-proof dependence: V1a source/artifact attestation is a structural
  prerequisite BEFORE P1/P2 live-entry rounds, not work scheduled after
  them. Require source-bound manifests and running hashes for both binaries
  on both firewalls plus kernel/classifier identity; mismatched userspace-dp
  artifact rejects the prerequisite before any dependent PASS. Permit-
  dependent consumer flips stay after P2 (V1b). No fixture-dependent live
  round reports PASS without complete artifact, kernel/classifier, restore,
  and packet-correlation evidence.
- R9 — Rotation/finality/downstream and asynchronous-writer residual:
  unfenced prefix rotation, `Terminal`-as-release, purged pre-park
  obligation, unserviced reaper backlog, an authorized xpfd route change
  before old I/O is final, or an unexpected external RPDB/FIB write can
  re-open M1/M3 risk. Mitigation for OWNED mutations is the single S4
  close/ACK/`IoRelease` rendezvous; immutable-q0 and receive-mode proof
  applies only across that enforced boundary. FRR/zebra has no mutation
  authority on admitted q0 tables (unsupported attachments are refused);
  R/A/K is admission/convergence evidence, never pre-install exclusion.
  RuleSubscribe and route-event callbacks trigger deny/revoke, periodic
  scans cover dropped edges, and the separate supervisor-stall watchdog
  bounds service liveness; this is a detection-bounded residual for
  out-of-model writers, quantified in §5 M1 and asserted with packet counts,
  not a zero-observation promise. Kill polarity: if the owner requires
  zero exposure against asynchronous external writers, keep P2 deny-only
  until a supported pre-change rendezvous/mediation exists.
 - R10 — Helper-incarnation confusion: a helper-only crash/restart (xpfd
  running) replays cached authority into a fresh store and attests
  vacuous-clean fences for a generation whose I/O it never saw; a
  forced SIGKILL during writer teardown leaves kernel I/O unprovable.
  Mitigation: (g) helper-incarnation handoff — durable per-exit
  clean/unclean verdicts bound to (boot, daemon_pid, procGen,
  helper_pid), replay gating (`BindHelperIncarnation`, unbound
  refuses), S4 revoke-to-CLOSING on every helper exit, fenced-
  generation import in the new helper, cumulative boot-bound
  `helper-unclean` freeze entries (reboot-only retirement). Kill
  polarity: any handoff cell failing (replay pre-handoff, missing
  verdict, generation reuse, cross-daemon inherit) keeps P2
  deny-only; the task-exit-finality alternative needs its own
  evidence before it can replace durable state.

## 7. Test plan

Per slice (each cell fail-on-revert; RED-on-revert evidence required in the
slice commit's Validation section):
- Entry order: V1a is a structural prerequisite BEFORE any P1/P2 live
  entry proof. Record source-bound build manifests, running-process hashes
  for xpfd and userspace-dp on both firewalls, and kernel/classifier identity.
  Any missing/stale identity or userspace-dp mismatch fails V1a and marks
  every dependent live result VOID before PASS is available. V1b permit-
  dependent consumer flips remain after P2. Every LANDED boundary test MUST
  assert the complete F0–F9 recipe matrix (all supplied kernel rows, including
  malformed/missing config, independent Kconfig fields, same-Uname distinct
  rows, and every boundary's pinned tuple) and the repo-level LANDED
  `pins_consistency` agreement test (distinct from recipe helper) comparing
  `bake.py` pin data, Go constants, and recipe pins. A subset,
  copied recipe without a LANDED executable matrix, or pin disagreement is
  not a PASS.

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
- P1-entry Q2 bypass-hunt cells (three independent packet/transition fixtures;
  each archives exact build, config, interfaces, tuple, timestamped harness
  sends/events, nft forward-rule/policy snapshots (and only configured rule
  counters), and sender/receiver counts; no product forward-drop counter is
  assumed):
  (1) Force bridge-family unsupported-only (`IsTransitBarrierBridgeUnsupportedOnly`)
  while bridge forwarding is configured. Expected product reason is
  `ErrTransitBarrierBridgeUnsupported`; the harness records
  `bridge_coverage_unavailable=1` and a `TRANSIT_BARRIER_DEGRADED` fixture
  event (harness labels, not claimed daemon telemetry). P1 admission is HOLD
  even though the inet-forward barrier remains installed. For attempted
  bridge plaintext, inspect nft forward policy/rules and receiver count:
  receiver must remain 0; any delivery confirms bypass and blocks P1.
  Fail-on-revert mutant treats degraded exit 0 as complete bridge coverage.
  (2) Send paired loopback-local and xfrmi-to-remote packets across the
  `fec7d18a3` exemption. Harness observations require the local packet to
  reach only local input (`loopback_local=1`, `loopback_remote_forward=0`,
  harness event `LOOPBACK_LOCAL_ONLY`). For the remote packet, record the harness
  event `TRANSIT_FENCE_PACKET_DROP` correlated with the attempted packet,
  inspect the nft default-DROP rule/policy, and require receiver count 0;
  `q0 delivered` is only a fence-mark witness, never drop evidence. Mutant
  broadens the exemption to a forward path.
  (3) Exercise every boot/first-install transition where capture or forwarding
  can become active. Before first possible forwarding, record the harness
  event `TRANSIT_BARRIER_DEFAULT_DROP`, inspect nft forward base-chain
  policy/rule state, and send a correlated probe; require receiver count 0
  and q0=0. The fence must be present before forwarding is enabled;
  `q0 delivered` is not a forward-drop counter. Mutant reorders the
  first-forward step ahead of fence installation.
  Missing/mismatched harness event, nft barrier state, receiver count, any
  unexpected receiver/q0 packet, or any unsupported-bridge PASS fails P1
  entry; "fail-closed at every intermediate" is unavailable until all three
  pass.
- P2-entry cells must PASS before production Permit code: exact admitted-RPDB
  IPv4/IPv6 fixture with PBR-free rib-group leak refusal and unrelated
  ingress-scoped-PBR control; M1 enforcement (ruleOps/facade/apply/FIB/
  receive-mode refusal cells for every q0-intersecting change incl the
  Dst-only rib-group rule; owned-vs-unowned tuple-match cell; per-image
  kernel-default inventory cell; PERIODIC AUDIT cells on the supervisor
  tick (NOT statusLoop): inject unowned rule → deny within 1s + poll +
  revoke, inject route-only change of EVERY shape (blackhole/redirect/
  connected/ECMP-half/link-local/off-allowlist) → same bound via the RAW
  FIB re-read + route baseline, plus audit-liveness cell; poll-error →
  deny cell; tick-order cell; install-inventory writer/record/reader
  cells (routing-owned type, corrected apply+clear points, table-999
  exclusion rationale); DIRECT-revoke cell (no seam) + single-sequence
  + episode-stability cell (same-key re-tick → no call); fib-audit tuple
  synthesis cell; FRR/Zebra authority cells: owner-approved supported
  configuration is refused unless `buildManagedSection`/`ApplyFull`/
  readback proves NO protocol can install, replace, withdraw, or change
  nexthops in any admitted q0 table; attempt each mutation for every
  configured protocol and assert refusal with FIB unchanged. `R/A/K` is
  admission/readback evidence only, never pre-install exclusion; attachment,
  config, and expected-kernel comparisons must agree before OPEN, while
  malformed/unmanaged state, R-only, and R+A HOLD. R+A+K may publish an
  admission state only after capped convergence (N=3 6s-separated samples
  then HOLD + alarm; no caller stalls on flapping RIB) + SPLIT sampling
  (lifecycle hooks full R/A/K synchronous with cap; 30s leg one K sample per
  tick vs previous, N=3 unstable ⇒ HOLD + alarm; 30s tick never delayed,
  #9693 owner never starved; cold-start-refuses-OPEN; degraded/hard/Clear/
  restart lifetime; queued/installed withdrawal; canary both families;
  output-shape pin). No R/A/K sample authorizes a zebra install.
  RuleSubscribe cell proves a real rule mutation edge triggers synchronous
  revoke; deliberately drop the netlink edge and require the 1s scan to
  detect it. For both cases record NEW q0 submissions during the ≤1s
  detection window and the in-flight I/O set at detection (bounded exposure,
  not zero); subscription failure blocks admission absent approved
  out-of-envelope rationale. The same bounded-count cell covers route-event
  FIB changes and dropped-edge periodic re-read; poll errors deny. A separate
  nonblocking watchdog test stalls the census/supervisor >3s and requires
  deny-only plus alarm from the independent watchdog. Record harness-observed
  NEW q0 packet counts from stall start through watchdog fire using
  timestamped harness sends plus observable nft-rule/receiver count
  snapshots (do not treat `q0 delivered` as a forward-drop counter or assume
  product forward-drop telemetry), and record the in-flight I/O set at
  watchdog fire. Exposure remains watchdog-bounded (~3s + revoke) but
  unquantified by evidence until these observations are captured. q0-path
  event cell records synchronous revoke, callback latency, and skipped
  coalescing but
  grants no pre-effective exclusion credit; M1
  in-flight fence sequence (revoke → Rust acknowledged close → cancel
  queued → account started + unreleased I/O → `FenceAuthorityAck` →
  immutable-routing + receive-mode gate → mutate → reopen) including the
  FIRST CHECK (writer paused after `pre_write_check`) + FIRST-CHECK-
  DEADLINE VARIANT (ownership-only transfer, BLOCKS, CLOSED+alarm, no
  ack), the DEFERRED-I/O CHECK, and the DOWNSTREAM-LIFETIME CHECK (mode
  enforcement + unreleased-I/O-prohibits-mutation + RFS fixture +
  missing-queue fixture + drift-freeze fixture + allowlist-member +
  4KSTACKS-absent + review-record-present + reject-mismatch-per-boundary
  (F0–F9 + per-boundary pinned-tuple match) cells); ack WIRE cells
  (`MSG_FENCE_CLOSE=4`/
  `MSG_FENCE_ACK=13`, `encodeFenceClose`/`decode_fence_close`,
  `SendFenceClose` full-round-trip submitMu + 5ms bound, interface
  method + S4 field/setter + live runtime selection, S4
  `fenceAuthority`, Rust match arm, Go accepted-set + `decodeFenceAck`,
  interleave-rejection cell); helper-handoff cells (R9O-01 — xpfd
  RUNNING throughout): helper-only crash (kill -9 helper → unclean
  record + freeze entry + S4 CLOSING; new helper stages but cannot OPEN
  while an ancestor obligation is unresolved; replay REFUSED pre-handoff
  (`ensureSubmitLocked` handoff-pending error, no announce on wire); old
  generation fence-FAILS in the new store); forced-kill-during-writer-teardown
  (SIGKILL escalation → `killed-during-teardown` unclean, same gates);
  clean helper replacement (fence-first → clean verdict bound to old+new
  incarnations → replay + inherit, no new unclean entry, prior entries
  persist; OPEN and mutation decisions still use the S4 table: same-env
  file-set/mirror-clear may OPEN after fresh checks but cannot mutate until
  reboot; sticky mirror or unresolved ancestor blocks OPEN); cached-replay-
  must-not-restore (reconnect attempt pre-handoff → refused; stale-conn-to-
  live-helper still replays); daemon-restart-ignores-handoff (handoff file
  from a prior daemon run → unclean path; freeze entries honored);
  M2 table-254 egress proof; M3 amendment cells (v36 +
  `MinProtocolIngressPrefixes=36` + MAX=64; owner-approval absent→P2 blocked;
  authored `0/0` reject vs implicit route/selector `0/0` grants nothing;
  missing route ownership→E22/no q0; partial ECMP blocks; legacy config
  without `ingress-prefixes` loads but cannot negotiate P-MECH; authored
  narrower than remote selector passes while wider/disagreeing selector
  refuses; route withdrawal revokes only after drain). Rotation remains
  fenced by the 6-step protocol, fresh-view `revalidate_permit_commit`,
  all-six-D5c revalidation, A-stamped/B-only-source E21 DROP, and
  drain-then-effective withdrawal cells (blocked-withdrawal,
  interleaving-blocked, immediate-when-idle, deadline-pre-park
  transfer-only + BLOCKS + CLOSED+alarm). Gate-2 recovery-entry wiring
  cell (`kernel_run.go:524-531`): unreadable `BootCurrent` must enter
  `verifyAndPromote`; with candidate running but non-member live Kconfig
  (e.g. `CONFIG_4KSTACKS=y`), Gate 2 must REVERT and never promote; also
  cover bad running package rows. This wiring evidence is distinct from the
  truth-table recipe. NAT-holder test seeds SNAT and NAT64 allocations,
  refuses a strict peer mirror replacement, proves the live allocator
  remains unchanged, and proves quarantine bit 127 survives worker-mask
  restore, retirement, expiry, and reseed; worker IDs remain 0–126. BPF
  ownership/generation cell proves maps are helper-private or epoch-owned,
  an old helper cannot mutate after handoff, and replacement cannot operate
  before ownership transfer. Stale Unix-connection cell closes/unbinds the
  old socket and proves no old fd or writer survives exit. Double-crash
  during unresolved handoff preserves cumulative freeze and cannot inherit a
  clean verdict. Blocker-5 entry cells remain deny-only and are detailed below.
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
  ownership-only reaper transfer pre-park (never self-`Written`, never
  terminalized while live); coordinated decision (journal-finalized →
  `resolve_write` rejects EXCEPT the transferred arm, which terminalizes
  exactly once; every other cross-pair late path false); obligation
  fixture in TWO groups — POST-PARK destroy-then-assert (target-CQE
  clears / failed teardown `Leaked` → fence ack FAILS / writer exit
  rows → fence ack FAILS) and PRE-PARK retain-then-assert (park→resolve
  `WriteStarted` BLOCKS then resolve/drain/ack; pause+pre-close purge →
  RETAINED + mutation prohibited; deadline-expiry in pause → transfer-
  only + BLOCKS + CLOSED+alarm, no ack; late coordinated resolve →
  `Terminal`; proven death via the writer's OWN join → `Leaked` row;
  success clears exactly once); death-witness distinguishing fixture
  (AF_XDP worker joined while `tx_delegated` paused pre-park → NO
  `Leaked`/terminal death state + NO fence ack until the writer
  resolves or its own join proves quiescence; retained handles +
  op→writer binding + join-outside-locks); deadlines (`d11-reaper` 1ms
  owner, 5ms ack deadline, cursor traversal with HWM pass boundaries
  per store, lateness fail-closed + regression polarity, STALE_SYNCED
  ceiling constants + 60s provisional cap, separated
  logical/physical/permanent-fencing outcomes incl cumulative ancestor
  rule, leak-store poison, ONE-SHOT marker consume-before-open +
  write-after-clean-fence + boot_id/triple-vs-authority-file match +
  independent new-run identity); fake-clock traversal fixture
  (full-capacity unexpired-prefix +
  beyond-budget entries, rotation coverage, journal wrap, churn with
  retire+insert-higher + resident low token serviced within
  K_FIRST=4 ticks worst case, mid-pass admission first-visited within 4
  (remainder ≤2 + next pass ≤2), every queue entry examined within
  K=2 ticks (positional rotation, refill beyond captured boundary),
  fill-to-513 refused with E40, retired-generation submit → STALE
  (admission refused into retired generations), epoch-Leaked fence
  FAIL, lock-contention try_lock refusal); fence-vs-handoff barrier
  cells (R9-SEC-02 — `cfg(test)` rendezvous + `Barrier`, no sleeps):
  (i) fence scan pinned inside the handoff commit window → no ack
  unless `WriteStarted`-visible OR `Leaked`-present (revocation
  never EFFECTIVE with pre-death buffer unwitnessed); (ii) handoff
  commit pinned inside the fence two-phase window (scan→rescan) →
  rescan sees `Terminal`+`Leaked`, ack still FAILS (epoch
  permanently fenced); mutants (each must flip its cell RED):
  single-lock scan (drop journal/obligation from the scan hold →
  (i) false-acks), split commit (release between terminalize and
  row insert; mutant pauses on the THIRD gate in the gap → rescan
  acquires the (c) trio → assert false-ack (RED) → release →
  mutant completes the insert); cross-restart marker fixtures
  (clean-stop→restart
  →crash→restart AND crash-without-prior-clean-stop AND clean same-boot
  restart with nonzero prior identity reopens AND boot-ID mismatch
  WITH CURRENT-BOOT authority (stale-marker-under-same-boot case 4
  — the (e) qualified form; cross-boot mismatch → fresh-init OPEN
  per the crash→reboot cell, NEVER freeze) → CLOSING/freeze AND
  crash-between-unlink-and-OPEN freezes AND failed/partial shutdown
  (verdict-not-ok → no marker) freezes AND mirror-set-clean-stop
  (no marker despite ok fence → restart case-(4)) freezes AND
  helper-crash-racing-shutdown (RMW-fail → re-check SET → no
  marker → case-(4); reaped+barred+empty-writers asserted) AND
  first-install
  (absent+absent → fresh init + OPEN) AND crash→reboot→re-admit
  (fresh admissible) AND clean-shutdown→reboot (stale marker
  discarded + OPEN) AND crash-after-nil-invalidation (retire-nil,
  ambiguous-nil, candidate-publish, postack-clear — each: INVALID
  present, no later fence, no marker → must freeze; proves
  absent+absent unreachable post-nil) AND nil-then-fence-then-clean
  (must OPEN) AND marker+INVALID pair (must freeze as
  inconsistent) AND crash-mid-tombstone-rewrite (kill -9 during
  persist → either version → must freeze) AND read-error freezes
  (EACCES/EIO either file → freeze+alarm; reboot retries) AND
  torn-authority (freeze+tamper alarm; reboot does NOT clear;
  `reset-torn-fence-authority` REFUSES valid/INVALID/absent files,
  writes sentinel BEFORE unlink (SIGKILL-between-steps: kill -9
  after sentinel → sentinel+torn → freeze; kill -9 after unlink
  → sentinel+absent → freeze via sentinel, NEVER first-install;
  re-run idempotent; SICK-DISK: sentinel write fails → NO unlink,
  torn intact, command errors, still frozen; sick-disk-plus-reboot
  → STILL FROZEN (torn pre-case-(2)); ONLY post-successful-reset-
  reboot admits; re-run-when-healthy recovers)
  AND torn-marker (freeze, never consumed) AND boot_id-unreadable
  (freeze+alarm) AND persist-failure outcomes (VALID-no-Store+retry;
  nil-live-freeze; fresh-init-freeze) AND epoch-flusher (four CAS
  sites signal; skip-if-stale; revoke never blocks) AND freeze-flag
  (case-4 writes boot-bound flag; post-reboot mutation allowed
  again; stale-unlink-failure refuses; stale-boot RESET on write
  (current-boot entry under stale boot_id → reset, no evaporate);
  write-failure → live-freeze-until-reboot + alarm + sticky
  daemon mirror; hygiene-unlink-failure → mutation-SET + OPEN
  iff admissible) AND crash-during-fresh-init (freeze; next
  reboot admits); no consumed-marker reuse;
  `resolveStartupAuthority` runs before any tick; `tryOpen`
  refuses unless startup admissible);
  quarantine
  PREINSTALL fixture (start with a provisional reservation NOT yet uncertain,
  run `retire_all` before join → SURVIVES; ordinary expiry HOLDs; ceiling
  reap bounded + counted); `Uncertain` is committed-but-inaccessible (no
  lookup visibility, no reuse, no rollback); restart resurrects no
  authority. Exercise partial NFQUEUE
  batches (disposed prefix vs uncertain suffix) without retry-forward;
  bound/remove verdict requeue and prove exactly-one `tx_delegated`
  writer + limiter behavior before a Permit arm; lifecycle cells (ALL
  in LIFECYCLE vocabulary — `SlowPathReinjector::new`,
  `tx`/`tx_delegated`, retained `JoinHandle`s, `spawn_named_worker`,
  `shutdown()`, `snapshot.rs` None-arm; `FallbackWhenNone`,
  `stop()`/`close()`, `D11-span` RETIRED): second-spawn failure
  (fail delegated `spawn_named_worker` → trusted sender dropped +
  trusted handle joined pre-`Err` (thread reaped, join proves it) +
  `snapshot.rs:669-680` None-arm pins `last_error` + no authority);
  handshake-`Fail` (`:875-885` → BOTH senders dropped + reaper
  stopped (`reaper_shutdown` + `unpark`) + ALL THREE handles
  joined outside locks + death scan asserts empty pre-`Err`;
  cell asserts the reaper handle joined (a fixture implementing
  writers-only teardown FAILS this cell — leaked reaper) + retry
  incarnation spawns exactly one reaper (no dual sweep));
  reaper-construction failure (fail reaper spawn → both senders
  dropped + both handles joined + `Err`, same discipline);
  double-stop (second `shutdown()` with slots `Done` → `Ok`
  no-op; with slots `Pending` → wait-on-`joined_done`-then-`Ok`);
  reaper-vs-stop arbitration (deterministic race harness driving
  BOTH winner orders + exactly-once take + exactly-once death
  decision; stop-loser waits `done_cv`, reaper-loser defers;
  contention → winner-retained proof + retry-terminalize, never
  re-take; steal path with `STOLEN_COMMIT_ZOMBIE` gauge; 1s total
  bound → `TEARDOWN_COMMIT_STALL` alarm + fail-stop abort (never
  proceed); reaper pending-age → `REAPER_COMMIT_STALL` + deny-all;
  steal-then-resume (stall reaper mid-commit → drive steal →
  resume reaper → original winner ABANDONS on `Done`/owner≠me:
  no proof-write, no second commit — exactly-once holds));
  normal-vs-unhealthy replacement (healthy → preserved Arc stays
  LIVE, generation fence retires old D11 gen, NO destructive
  shutdown in `stop_inner`; unhealthy → else-arm `old.shutdown()`
  before new publish, never republish-after-shutdown);
  last-Arc (`shutdown_skipped_drop` alarm on undriven `Drop` + no
  join; every `SlowPathReinjector` incarnation's writer handles +
  reaper handle prove-joined in `shutdown()` + writer quiescence
  before join).
- E-row taxonomy cells: the closed table is `reason_for_erow` (E1–37 →
  reason byte, `ipsec_inner_queue.rs:94-129`), validity {5,6}∪[32,60]
  (`:88-90`, `reason_map_is_closed` test), Go mirror
  (`pipeline.go:1511-1543`). Fault-injection for EVERY touched E-row
  asserting counter + event exactly once with no unmapped terminal.
  BYTE ALLOCATION (CHOSEN — the set is fully assigned, so validity
  extends to {5,6}∪[32,63]): 61 `FENCED` (new E-row 38 → 61; SPLITS
  `Fenced` from `Stale`: new `PipelineStats.Fenced` +
  `xpf_ipsec_capture_fenced_total`, `OUTCOME_FENCED=6` + `fenced` label
  already exist; move `pipeline_9506_test.go:607` expectation);
  62 `AMBIGUOUS_DROP` (tie-break ambiguous-DROP; new E-row 39 → 62);
  63 `JOURNAL_FULL` (journal admission refusal beyond 512 live records;
  new E-row 40 → 63; the K-denominator bound made visible).
  `Written` needs NO deny byte (success terminal: `completed_written`
  counter + ledger `Written` terminal + D11 event — named, not
  byte-mapped); `Refused` needs NO single byte (each refusal carries
  its specific deny reason); `Uncertain` keeps 48, E21 keeps 45.
  DECODER/FIXTURE UPDATES (all REQUIRED): `is_valid_reason_byte`,
  Go `Valid()`, `String()` arms, `reason_for_erow` arms,
  `reason_map_is_closed` update, NEW Go exhaustiveness test (no Go
  closed-range test exists today), spot pins. New/changed mappings
  (all REQUIRED): E38/`Fenced`, E39/`AMBIGUOUS_DROP`, E40/`JOURNAL_FULL`
  (+ fill-to-513 refusal cell asserting E40 exactly once, no admit),
  `Cancelled`→`statsCancelled`+`xpf_ipsec_capture_cancelled_total`+ledger,
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
3. **Can M1 admit a precisely inventoried RPDB state, fence every
   xpfd-owned q0 mutation across old in-flight I/O, hold the routing
   environment through the owned-change CLOSED interval, and can M2 prove
   actual q0 egress domain before emission?** A PBR/FBF-only refusal is
   disproven as a complete fallback: a Dst-only rib-group rule may still
   steer q0, while unrelated ingress-scoped PBR need not. KILL POLARITY:
   if the admitted-RPDB predicate, owner-approved configuration restriction,
   or S4 pre-effective rendezvous cannot be enforced for every supported
   owned writer; if an FRR/zebra path can install into an admitted q0 table;
   if RuleSubscribe cannot be installed and no approved justification removes
   that external writer from the support envelope; if the rules+FIB audit
   cannot bound dropped-event detection; or if M2 cannot distinguish table
   254, all policy Permits remain deny-only and re-plan triggers. External
   writers are detection-bounded only (≤1s of possible NEW q0 submissions
   under changed state plus the measured in-flight set); R/A/K is admission/
   convergence evidence, never pre-install exclusion. If the owner requires
   zero exposure from external asynchronous writers, P2 remains deny-only
   until a supported pre-change rendezvous exists. Assessment: all are
   blocking P2-entry gates; no permit implementation is authorized until
   they pass.
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
 8. **Does the helper-incarnation handoff actually retire every way a fresh
  store can speak for a dead generation — or does a quieter path (stale
  Unix conn surviving the exit, BPF-map rows outliving both helpers,
  or a second crash inside the handoff window) bypass it?** The design
  gates replay, revokes S4, fences generations, and persists verdicts —
  but each mechanism has a seam (conn liveness vs incarnation binding,
  map ownership vs store ownership, verdict write vs crash). KILL
  POLARITY: a demonstrated bypass kills (g)-as-designed — re-plan on
  conn-bound incarnation tokens and/or map-generation fencing.
  Assessment: no bypass demonstrated; the fail-on-revert handoff cells
  include helper crash/kill, stale-socket close+unbind, BPF ownership/
  generation, clean replacement, replay refusal, cross-daemon restart, and
  double crash while an ancestor is unresolved. The independent >3s
  supervisor-watchdog stall cell is required as well; any nondeterministic or
  unbuildable cell reopens this question.

## 9. Evidence appendix (historical source reads + v14 current-tip audit; cwd `/var/tmp/worktrees/9506-research`)

```text
# v13 baseline snapshot through `028c4e4e2` (historical; v14 current pin is below)
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

 ```text
 # v10 additions (2026-09-27; origin/master = 3be469bc3, re-verified)
 grep -rn 'ipsecOverlayAcked' pkg/daemon/*.go  # ack :237/:332/:361/:366
                                               # (reconcile); nil :17/:24 (fence),
                                               # :287 (reconcile), :1519/:1689 (wiring)
 sed -n '270,446p' pkg/daemon/ipsec_reinject_supervisor.go  # 4 permit CAS sites
                                                             # :298/:340/:365/:435
 sed -n '121,162p' pkg/cluster/sync_boot_incarnation.go  # bootIDPath + parse
                                                          # (zero-fallback NOT reused)
 sed -n '60,120p;630,683p' userspace-dp/src/afxdp/coordinator/reconcile/{teardown,snapshot}.rs
                                               # preserved-Arc clone + republish arms
                                               # + None-arm fallback (:669-680)
 sed -n '799,907p' userspace-dp/src/slowpath.rs  # new(): spawns :811/:834,
                                                  # handshake :866-888; JoinHandles discarded
 sed -n '272,407p' pkg/dataplane/userspace/process_supervisor.go  # crash→disarm→restart
 sed -n '518,617p' pkg/dataplane/userspace/process.go  # stopLocked + SIGKILL :609
 sed -n '57,113p' pkg/nfqueue/reinject_socket.go  # announcePayload replay on reconnect
 sed -n '551,558p' pkg/upgrade/kernel_run.go  # Gate 2 running==candidate only
 sed -n '84,130p' pkg/upgrade/kernel_status.go  # ReadChannelStatus = reporting
 sed -n '376,445p' scripts/dist/sign.py  # nonempty guest_kernel only (gap, executed)
 sed -n '700,760p' scripts/dist/publish.py  # manifest↔inventory agreement only (gap)
 sed -n '1185,1230p' scripts/image/validate.py  # scenario A floor (gap)
 curl …/dists/resolute-security/…/Packages.gz  # member rows 7.0.0-30.30 + SHAs
 git ls-remote …/+git/resolute Ubuntu-7.0.0-30.30  # tag → 399867a7
 git clone --depth 1 --branch Ubuntu-7.0.0-30.30 …  # commit d974a4063
 sha256sum linux-image/buildinfo debs  # MATCHES Packages (6f01659e/24af1791)
 grep CONFIG_ buildinfo config  # 4KSTACKS absent; BRIDGE=m; NF_TABLES_BRIDGE=m
 grep/sed member tun.c/dev.c/ip_input.c/ip6_input.c  # B1-B8 branch lines (record §7)
 python3 ENOTSOCK probe  # sendmsg on TUN char fd → errno 88 (non-socket)
 python3 sign/publish/floor/member probes  # gaps SIGN/PUBLISH/PASS -31; predicate REJECTs
 # v12 additions (full-tuple recipes + corrected ENOTSOCK + flag/sentinel cites)
 awk-extract f0f9-recipes.md; USE_SUDO=1 ./run_all.sh  # ALL-HERE-OK (A+B+same-uname+skews)
 sha256sum -c <v12 pins>  # 15/15 OK (extraction stability)
 sudo -n TUNSETIFF bind + ctypes sendmsg  # bound fd errno 88; wrapper/NULLCTL/PAIRCTL;CLEANUP
 grep -rn callers setHostInputFenceOverlay/clear*  # conntrack :274/:280, reconcile :290 (census shut)
 # v14 additions (round-13 impact addendum + post-pin path intersections)
 git rev-parse origin/master  # observed 0ab1c7d87; v14 pin at header
 git log --oneline 2ccea8434..origin/master  # 11 post-pin commits
 git diff --name-only 2ccea8434..origin/master | wc -l  # 309 changed paths; intersections reviewed in §4.5, not a zero-impact assertion
 git show --stat fd32d2df5  # holder capture/replace; §5 quarantine census adds snapshot/restore/reseed paths
 git show --stat 2ccea8434  # 34 files; daemon_apply_commit.go + daemon_ha_sync.go are M3/HA consumers
 git diff 2ccea8434..origin/master -- pkg/daemon/daemon_apply_commit.go pkg/daemon/daemon_ha_sync.go pkg/cluster/sync_conn_config.go userspace-dp/src/afxdp/ha/session_import.rs userspace-dp/src/nat/allocator.rs pkg/routing/vrf.go  # post-pin callsites re-anchored in §4.5
 # v11 additions (retained recipes + member-tree deltas + lifecycle cites)
 curl -O linux-headers/linux-modules 7.0.0-30.30 debs; sha256sum  # f3be8e8d/d61aa07f MATCH
 git rev-parse 'Ubuntu-7.0.0-30.30:<f>' (6 files)  # blob SHAs (record §8)
 sha256sum u30bi/.../config  # b07d3cb0… (full config pin)
 grep -n 'phydev|phylib|hwprov|hwtstamp' member tun.c  # ZERO hits (B7-ts)
 sed -n '67,112p' member net/core/timestamping.c  # defer gate (B7-ts)
 awk-extract f0f9-recipes.md; ./run_all.sh  # MATRIX: ALL-HERE-OK (15 scripts)
 sha256sum -c <recorded pins>  # 15/15 OK (extraction stability)
 grep -rn 'setHostInputFenceOverlay|clearHostInputFenceOverlayAfterAck' pkg/daemon/
   # callers: conntrack :274/:280 (retire), reconcile :290 (restore) — binding complete
 ```

 Prior-review note: the Sep-25 delta assessment comment (issue #9506) and its
 D11-clarification comment were used as the starting inventory and every load-bearing
claim in them was re-verified; v10–v13 rechecked their then-current
load-bearing cites at `3be469bc3` (nil/epoch, helper lifecycle, spawn,
and image-gate sites). V14 separately audits the post-pin path
intersections through `0ab1c7d87` in §4.5. The two corrections versus
Sep-25 stand: (a) F1 landed (#11107), (b) v35.
