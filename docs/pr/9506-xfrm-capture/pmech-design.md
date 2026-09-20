# P-MECH mechanism design: fail-closed zone enforcement on the S5-diverted path (#9506)

- Status: CONDITIONAL PLAN AMENDMENT (owner-requested; answers Step-0 unblock option 1 and r6 §9.1 Q1);
  G3 INPUT session atomicity remains an explicit owner-decision/PLAN-KILL boundary in D12a/§5.5.
- Branch: `research/9506-pmech-design` (worktree `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign`), master base `1a6952b61`.
- Date: 2026-09-20.
- Sources: r6 plan `/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md`
  (`research/9506-reground @ b4f1d3035`, 2111 lines) + companion
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-delta.md` (126 lines);
  r5 plan `/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md`
  (825 lines); Step-0 gap report `/tmp/pmech-gaps-full.json` (G1–G6); master code at `1a6952b61`.
- Scope: the zone-evaluation mechanism for S5-diverted IPsec-inner traffic ONLY (G1–G5 + G6 accounting).
  Non-goals: implementation, tests, live validation runs, observer exactness (O-*), verdict flips (V-FLIP),
  doc-sync flips (D-SYNC), shadow/flip protocol (owner call pending — NOT designed here beyond the
  evaluator's shadow contract in §2.6).
- Path convention: every file path in this document is ABSOLUTE and worktree-rooted at
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/`. Relative paths are banned by design brief.

## §0 Decision index

| Gap | Decision (one line) | Section |
|---|---|---|
| G2 tunnel→zone | if_id-keyed snapshot map (`XFRMIfNameAndID` join); UNZONED/AMBIGUOUS → DROP-and-count; authority split config/daemon/P-MECH/S4 | §1.1–§1.3 |
| G2 S12.5 #5 re-sign | **Y** — built mechanism conforms to every normative clause (citations re-grounded; line numbers drifted) | §1.4 |
| G2 S12.5 #6 re-sign | **Y on the choice, identity supplied herein** (`D_usp1` = kernel main table, non-VRF) + 4 kill-conditioned must-proves M1–M4 | §1.5 |
| G2 K2 | NOT triggered. Trigger conditions + re-plan needs stated plainly | §1.6–§1.7 |
| G1 evaluator | 3 layers: Go pre-gate hook + Rust worker-pipeline adjudication via dedicated per-worker queues + `allows()` final guard | §2 |
| G1 doubt | 9-arm definition; doubt → DROP-and-count (enforcing) / divergence-counted ACCEPT or shadow-unavailable (shadow) | §2.6 |
| G3 order | Worker order BY CONSTRUCTION (screen→session→static-DNAT→DNAT→route→policy→SNAT→install); consult/skip table; Reject≡Deny V1 | §3 |
| G3 INPUT session boundary | Full stateful INPUT parity is unresolved: Option A stateless scope cut or Option B proven two-resource protocol; no broad INPUT permit claim before owner authorization | §2.5/D12a, §3, §5.5 |
| G3 sessions | `SessionKey` + new `Ipsec(if_id)` tunnel discriminator (forward + reverse); ambiguity → doubt → DROP; INPUT session HITs revalidate NAT, misses are D12a-gated | §3.5 |
| G4 deny | Reuse `PolicyDeny`/`UNATTRIBUTED_POLICY_ID` + per-stage events/counters; full taxonomy → DROP-and-count, no silent drops | §4 |
| G5 slice | File list + order + live-proof validation bar + kill conditions; S9.5 INPUT permit work is blocked until D12a owner decision | §5 |
| G6/threat | Mechanism targets r6 §1.1/§1.3 residuals; r5 §1 framing cited as STRUCK; narrow delta recorded | §6 |

Conventions: MUST/NEVER etc. per RFC 2119. "DROP-and-count" always means: terminal DROP verdict on the
held NFQUEUE packet (or q0 refusal for bytes never admitted) + exactly one increment of the named counter
+ (Rust side) the named deny event where specified. No silent drops exist in this design.

---

## §1 G2 FIRST: tunnel→zone derivation + S12.5 #5/#6 re-sign (r6 §9.1 Q1 answer)

### §1.1 Tunnel→zone derivation rule

**D1 (derivation function).** The tunnel zone is derived at SNAPSHOT-BUILD time (daemon, same generation
that stages capture) as an if_id→zone map, and consumed per-frame on the divert path:

1. Inputs (all fail-closed validated before use):
   - Authored: `vpn.BindInterface` per VPN in `cfg.Security.IPsec.VPNs`, and every
     `security-zone <z> interfaces <ref>` member in `cfg.Security.Zones` (compiled `*config.Config`).
   - Derived: `if_id` via `XFRMIfNameAndID` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/xfrmi.go:52`,
     single source of truth; `if_id = stIndex<<16 | (unit+1)`; `if_id == 0` ⇔ no device).
   - Live: kernel ifindex via `netlink.LinkByName(ifname)` (already resolved per tunnel at
     `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go:304-311`).
   - Generation: the capture generation (`ipsecCaptureQueueKeys(cfg, generation)` at
     `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go:285-332`)
     plus the authorizing snapshot's `Generation`/`FIBGeneration`
     (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go:561-562`).
2. Lookup path:
   - Build: for each zone member ref with `XFRMIfNameAndID(member).if_id != 0`, record `if_id → zone`.
     This is the SAME if_id join `collectZoneInterfaceRefsAST` uses
     (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/compiler_ipsec_plaintext_warn.go:262-268`),
     but over the compiled config at runtime rather than the AST at advisory time.
   - Per-frame: `CaptureOrigin.STN` (which is ALWAYS the authored `vpn.BindInterface` —
     `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go:326` — and is
     re-validated to `if_id != 0` at divert-spec build,
     `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go:37-40`)
     → `if_id` → zone. Cross-check `Origin.OwnedIfindex` against the live ifindex for the derived
     ifname (name-reuse protection; mismatch → doubt → DROP — the T12 device delete/recreate/name-reuse
     cell already demands DROP-and-count on ifindex mismatch, r6 §3.5 item 4a).
3. Fail-closed outcomes (no default zone, no silent inheritance):
   - UNZONED (no zone claims the if_id) → DROP-and-count (`zone_gate_unzoned_total` + deny event, §4).
   - AMBIGUOUS (≥2 zones claim refs resolving to one if_id) → DROP-and-count (`zone_gate_ambiguous_total`)
     + alarm. This is REQUIRED (not inherited first-writer-wins) because: (a) the strict commit gate
     `validateZoneInterfaceMembershipStrict`
     (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/compiler_validate_strict_zones.go:274-314`)
     has a cross-spelling blind spot for st refs — bare `st0` in zone A claims key `st0` while `st0.0`
     in zone B claims key `st0.0` (`zoneIfaceLogicalKeys`,
     `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/compiler_validate_strict_zones.go:213-240`,
     fans bare refs down only over DECLARED `cfg.Interfaces` units, and st units are usually undeclared
     per #4515), so the SAME xfrmi (if_id 1) passes the gate double-claimed; (b) `InterfaceZoneMap`
     (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/host_inbound_effective_view.go:101-154`)
     would then silently first-writer-win it ("evaluating traffic against the wrong zone's policy" —
     the gate's own rationale at `:302`); (c) tunnel zone selects FULL policy, not just service tokens,
     so silent resolution is a mis-zoning risk. The AMBIGUOUS refusal mirrors #7509/#6727 (same-ifindex
     contest → entry REMOVED from `ifindex_to_zone_id`, "both halves now refuse").
   - `if_id == 0` → refused at staging (existing wiring errors) + per-frame doubt → DROP (defense in
     depth; the registry `Register` also refuses empty STN —
     `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/origin.go:52-58`).
   - Stale generation (frame's captured config/fib generation ≠ worker's current) → DROP-and-count
     (fencing, #7167 invariant 5; §2.4).

**D2 (why if_id-keyed, not string-keyed).** Bind `st0` + zone `st0.0` are the SAME device (both if_id 1 —
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/xfrmi.go:50-56`,
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/README.md:1299-1302`). String matching
would mis-zone that pairing — the EXACT #5619 bug class
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/compiler_ipsec_plaintext_warn.go:246-253`:
"Matching literally would miss that pairing and report a ZONED tunnel as unzoned").
Different units (`st0.0` vs `st0.1`) are DIFFERENT devices (if_id 1 vs 2) with SEPARATE capture queues;
zone does NOT inherit across units (a zone on `st0.1` does not zone a bind of `st0.0` — the bind is
UNZONED → DROP with a clear counter; the #5619/#4515 advisory already warns on such configs).

### §1.2 Zone/owner authority (resolves "PROPOSAL/S4-owned", r6 §3.5 item 8)

**D3 (authority split).** r6 §3.5 item 8 deferred tunnel→zone as "PROPOSAL/S4-owned". This amendment splits
permit authority from zone semantics — S4 keeps the former, never owns the latter:

| Artifact | Owner | Grounding |
|---|---|---|
| Zone definitions (`Security.Zones`, member refs) | config/compiler (existing) | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/compiler_security_zones.go`, strict gates `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/compiler_validate_strict_zones.go` |
| if_id→zone map publication (per capture generation) | daemon snapshot/staging path (extends `ipsecCaptureQueueKeys` generation) | wiring `:285-332`; snapshot `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go:560-567` |
| Zone CONSUMPTION on the divert path (Go pre-gate + Rust worker entry) | P-MECH (new; this design §2–§3) | — |
| Permit/epoch/rotation authority (OPEN/CLOSING/CLOSED, `tryOpenPermit` requires `ipsecReadySafe`) | S4 (unchanged) | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_reinject_supervisor.go:349-351`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_topology_owner_9506.go:184-243` |
| Rust snapshot zone maps (`ifindex_to_zone_id`, `ifindex_unambiguous_zone_id`) | forwarding build (existing) | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/forwarding_build/interfaces.rs`, populated from snapshot interface rows |

No dual ownership: S4 gates WHETHER capture is authorized (topology/permit/epochs); it never answers
"which zone". Zone answers come only from the config-owned map above. The r6 §3.5 item 8 citation
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/zones_host_inbound.go` effective tokens) remains the HOST-INBOUND service-token source — P-MECH does
not re-derive host-inbound tokens; INPUT-hook frames consult the existing host-inbound machinery (§3.3).

### §1.3 Alternatives rejected (G2 derivation)

- R1 (inherit `InterfaceZoneMap` string resolution incl. first-writer-wins and unit→base fan): REJECTED.
  Reintroduces the #5619 spelling bug; silently mis-zones cross-spelling double-claims the strict gate
  misses (§1.1.3); drags unit-1 claims onto unit-0 devices. Deterministic ≠ correct for policy selection.
- R2 (derive zone from outer peer / underlay physical interface): REJECTED. Violates r5 H2
  tunnel-identity ("never outer phys zone", r5:405) and #7167 invariant 2
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:53-56`: passing a physical ifindex "would adjudicate inner traffic under the
  underlay's zone").
- R3 (default zone / unzoned-permit): REJECTED. Junos default-deny parity (#3405); the #5619 advisory's
  zoned/unzoned partition exists precisely because unzoned must stay visible; unzoned-permit would
  resurrect struck r5 §1 fail-open forwarding for unzoned tunnels.
- R4 (S4 owns zone semantics, permit + zone in one authority): REJECTED. Concentrates two failure modes;
  S4's permit evidence (topology census) cannot answer zone questions; keeps the G2 deferral alive instead
  of closing it.

### §1.4 S12.5 item #5 re-sign: Y

**D4: Y on item #5 (re-entry metadata: structural queue provenance + write ACK) AS WRITTEN in r6 §6.**
Clause-by-clause conformance at master `1a6952b61` (r6's `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs` line numbers drifted as the file
grew to 2237 lines; every normative clause re-grounds below):

| Item-5 clause (r6 §6) | Verdict | Master anchor |
|---|---|---|
| `enqueue_adjudicated` structural provenance; 9506 submits tagged `PacketQueue::Adjudicated` | CONFORMS | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:1056-1061` (`enqueue_adjudicated`), `:1254-1260` (9506 `submit_adjudicated_frame` sends `PacketQueue::Adjudicated` on `tx_delegated`) |
| TC mark `0x58465001` IFF `queue_mapping == 1`; others cleared | CONFORMS | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:35-41` (`ADJUDICATED_QUEUE_MAPPING`, `ADJUDICATED_TRANSIT_MARK`), `:183-187` (clear-then-set), `:282-283` (install) |
| Fence `(xpf-usp1, exact-mark)` conjunction; mark never admitted without its interface | CONFORMS | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nftables/transit_barrier.go:22-43` (`ForwardFenceMark`, `AdjudicatedTransitMark`), `:227-254` (`emitTransitFencePinhole`: `iifname` + `mark` conjunction; empty-ifname/zero-mask refused) |
| Validated `{family,hook,owner,stN,owned_ifindex}` + preserved `nfgen_family`/`hook`/`ifindex` | CONFORMS | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/origin.go:26-35` (`CaptureOrigin`), `:72-86` registry, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/nfqueue.go:335-358` (provenance fields observational until validated) |
| inet accepts `{AF_INET,AF_INET6}`; bridge only `AF_BRIDGE` | CONFORMS | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/origin.go:82-86`, `:120+` (`normalizeCaptureFamily`); `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/nfqueue.go:181-186` (`OpenFamily` bridge bind) |
| Metadata/ifindex/name-reuse mismatch → DROP-and-count, never q0 | CONFORMS | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:312-334` (`Enqueue`: `ValidateProvenance` → `ProvenanceMismatches++` + terminal DROP) |
| Bridge rows never enter q0; inet INPUT has no q0 writer (it terminalizes the held original through the supervisor committer) | DESIGN CHANGE (P-MECH) | Current Go gate rejects both classes at `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:542-548`; S9.1 narrows rejection to bridge/unsupported hooks, admits inet `{forward,input}`; Rust keeps bridge refusal, while §2.1/§2.5 add the conditional INPUT terminal path |
| INPUT permit terminality is an authoritative supervisor `InputPermitCommitter` ACCEPT, never q0 | DESIGN ADDITION (P-MECH; conditional on D12a) | §2.1/§2.5: exact origin + epoch identity + supervisor live-permit/queue/snapshot check; invalid/late completion is DROP; no broad stateful claim until D12a |
| Existing `CompletionAccepted`/`CompletionWouldReinject` not terminal; `ReinjectLease` held through TUN write + epoch-tagged completion ACK | CONFORMS for FORWARD | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:32-44` (`ReinjectLease`), `:623-634` (pending through ACK); `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:221-232` (`ReinjectCompletion`); `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:1434-1437` (lease recheck immediately before write) |
| Revocation cancels queued leases; stale → one DROP; `T_ack≤5ms`; timeout uncertain/no-retry | CONFORMS | `Cancel`/`CancelReinject` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:928`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/reinject_socket.go:184-205`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs` cancel paths); `AckDeadline` default `5ms` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:259-260`); `resolveUncertain` + no-retry terminal rule (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:690-697`, `:751+`) |
| Only successful write commits; ambiguous → DROP-and-count / possibly-emitted-never-retried | CONFORMS | `decide_resolve` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:418-432`: Written/Refused/Uncertain + Fenced/Denied/Accepted/WouldReinject); completion decode incl. Fenced/Denied/Accepted/WouldReinject (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:880-885`) |
| MTU-exceeded (live TUN MTU), queue-full, rate-limited → DROP-and-count | CONFORMS | `EnqueueOutcome::{Accepted,RateLimited,QueueFull,MtuExceeded}` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:103-111`); 9506 submit path enforces all three with counters (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:1195-1249`, `:1262-1300`) |
| Single-writer q0 + coupling/limiter proof-or-split as S4 must-proves | MUST-PROVE (carried) | Single-writer stated (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:35`: "Queue zero is opened by the sole adjudicated xpf-usp1 writer"); adjudicated+delegated STILL share `tx_delegated` + one `RateLimiter` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:660-661`, `:1056-1081`) with per-class admitted/refused counters (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:448-451`) — the §3.5-item-2 proof-or-split cell (G1/T8) is test evidence, not code. Item 5 requires these AS MUST-PROVES ("are S4 must-proves under this sign-off"), which is satisfied structurally; the proof itself is owned by S4/S7 validation and is carried as G5 kill condition K-M5a (§5.4), NOT a re-sign blocker |

Reasoning: item 5 signs the MECHANISM CHOICE (structural queue provenance + write ACK instead of
topology/VRF+policy-routing). That choice is what S4/S5 built and 2a/2b/2c witnessed end-to-end
(`2d647dd37`, `a92a40a2c`, `1a6952b61`). r6 §6's own rule — "Y on both authorizes S4 on the §3.5
must-prove list" — confirms Y never meant "all proven"; it meant "proceed to prove". One must-prove
(coupling) remains open as validation evidence with a kill condition. Recommending N over a validation
residual, after the mechanism proved green on live SAs, would be disproportionate and would not change
the fail-closed direction (coupled loss is DROP-and-count per §3.5 item 2).

### §1.5 S12.5 item #6 re-sign: Y on the choice, identity supplied herein, 4 must-proves

**D5: Y on item #6 (topology: one shared adjudicated outlet + mark isolation) on the architectural choice,
with the concrete `D_usp1` identity WRITTEN INTO THIS AMENDMENT (satisfying §6's "MUST be written into
this sign-off before the owner can answer Y") and four enforcement clauses converted to kill-conditioned
P-MECH/G5 must-proves M1–M4. A bare "Y as written, nothing more needed" would be FALSE — this section
states exactly what conforms, what was never done, and what must still be proven.**

D5a (the identity — written here). `D_usp1` = the kernel MAIN routing table (inet, table 254;
IPv6 main) reached via the standard RPDB fallback (no xpf-installed rule steering q0-ingress/inner
traffic elsewhere — subject to must-prove M1), entered through the daemon-owned masterless `xpf-usp1`
TUN, with NO admitted xfrmi enslaved to any master. Answers to §6's mandated questions:

- Concrete main-table identity: main table 254 (inet) / main (inet6), fallback prefs 32766/32767.
- Is it an l3mdev VRF master? NO. (Main is not an l3mdev; `xpf-usp1` enslavement is refused by census —
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_topology_owner_9506.go:206-208,238-242` → `ipsecReadyUnsafe`, never OPEN.)
- Non-main policy-rule/table selection: REJECTED for V1 (any must-prove failure → §1.6 K2 path).

D5b (clause table — honest conformance):

| Item-6 clause (r6 §6) | Verdict | Anchor / gap |
|---|---|---|
| ONE shared adjudicated outlet (single `xpf-usp1` q0, all routed-inet tunnels via bounded channel) | CONFORMS | Single TUN, q0 discipline (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:35-38`), bounded `tx_delegated` (`:749`), per-tunnel NFQUEUE capture + queue fairness (S3/S4/S5 as landed) |
| MARK-BASED ISOLATION (TC-cleared default + exact fence conjunction) INSTEAD OF per-VRF/RG TUNs | CONFORMS | §1.4 fence/TC rows; `TunSink` measurement-only, explicitly NOT a re-entry path (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/tunsink.go:11-15`); no 9506 TUN creation (no `TUNSETIFF` outside sink + slowpath outlets) |
| Limits q0 to one configured routed-inet domain `D_usp1` | CONFORMS-ARCHITECTURALLY (single outlet, single census); per-packet domain enforcement GAP → M3 | No per-packet VRF/RG/FIB check at admission (the `VRF` field on `IpsecCaptureQueue`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go:34`, feeds ONLY `FragmentKey`, `:233`); §3.5-item-6 overlap admission check + commit-time domain revalidation NOT in code |
| Concrete main-table identity written into sign-off before Y | SATISFIED HERE (D5a); was NEVER written before (no `D_usp1` symbol, no record in 9 issue comments or `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/docs/log` — negative grep + remainder map) | This §1.5 is the record. Owner rejection of D5a = N → §1.6 |
| Owner rejects non-main; answers l3mdev question | ANSWERED HERE (D5a) | Same vehicle |
| No admitted xfrmi VRF-enslaved (incl. to `D_usp1` itself); `xpf-usp1` unenslaved | CONFORMS | Census → Unsafe/Unknown → never OPEN (§1.4 row); "incl. to `D_usp1` itself" vacuous-and-true (main is not a master; any enslavement refused regardless of master type, `:229-236`) |
| If `D_usp1` were real-VRF/non-main → N for V1 | NOT TRIGGERED (D5a is main/non-VRF) | — |
| Packet bytes carry no VRF/FIB identity | CONFORMS | `SubmitFrame{lease,flow_tag,flags,origin,bytes}` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:141-147`) + `CaptureOrigin{family,hook,owner,stn,owned_ifindex}` — no FIB/table/VRF field on the wire or the struct |
| Every other VRF/RG/FIB + VRF-enslaved capture → DROP-and-count | COARSE ✓ / FINE ✗ → M3 | Coarse: VRF-enslaved xfrmi ⇒ permit never opens (STRONGER than per-packet drop — all capture refused). Fine: no per-packet "other VRF/RG/FIB" admission check (same gap as overlap row) |
| Owned-egress via fence conjunction + MAIN-TABLE EGRESS ORACLE | Fence ✓ / ORACLE ✗ → M2 | Fence admits only marked q0 frames (§1.4); NO egress oracle exists (no post-write domain confirmation; `delivered` witness counts fence matches, not egress table) |
| Shared-device hook/conntrack inventory replaces per-VRF inventory (§3.5 item 4) | GAP → M4 | S4's conntrack work is host-input-fence revocation (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/docs/log/9506-s4.md`), NOT the q0 shared-device inventory; RPF only a bringup warning (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:2044-2081`); zero hook/RPF/martian/`accept_local` inventory hits in 9506 S4/S5 Go path |
| `W×I≤128` retired | CONFORMS | No per-(worker,instance) TUNs; live bounds are channel depth + rate limits + fairness + 32-tunnel admission (r6 §3.5 item 7) |
| Multi-domain / VRF-singleton / bridge-permit revives option C | CONFORMS (no such claim in tree; bridge-permit refused at two layers, §1.4) | — |
| RPDB steers nothing off main (implied by "ONE main-table domain": PBR/rib-group/next-table rules sit BEFORE main — `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/routing/rules.go:88-90`, `:64-68`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/routing/pbr_applied_7422.go:22-24` — and CAN match re-injected inner packets; NO iif-`xpf-usp1` exclusion exists in any rule manager — negative grep) | GAP → M1 | The "no rule steers q0 ingress elsewhere" premise (r6 §3.1) is UNPROVEN and likely FALSE under PBR/FBF configs |

D5c (must-proves M1–M4 — kill-conditioned, owned by G5 §5):

- M1 (RPDB non-steering proof): prove (live, loss cluster) that with the acceptance config's RPDB
  (PBR/FBF, rib-group, next-table, probe-pin bands), re-injected inner packets resolve via main and no
  earlier rule diverts them — OR ship an iif-`xpf-usp1`-scoped exclusion / RPDB-audit gate that fails
  closed (tunnel DOWN + counted) when a steering rule appears. Kill: steering observed and un-gated →
  V1 scope refuses PBR/FBF coexistence (config gate) or K2 re-plan (§1.7).
- M2 (main-table egress oracle): build the oracle item 6 names — post-commit confirmation that q0-egress
  resolved in main (wire-observed egress + RPDB snapshot check at T2, or equivalent). Kill: un-oracleable
  egress → no V1 claim of single-domain re-entry.
- M3 (overlap admission + commit revalidation): at admission, reject overlapping inner prefixes/addresses
  among tunnels assigned to `D_usp1` (the §3.5-item-6 check); at commit, revalidate domain/snapshot before
  the q0 lease/write; per-packet other-VRF/RG/FIB → DROP-and-count. Doubles as the session-aliasing
  detector (§3.5). Kill: overlap admitted silently → tunnel DOWN; overlap + SNAT in one instance → V1
  refuses the combination (VRF separation required).
- M4 (shared-device inventory): inventory every netfilter hook, conntrack/NAT zone, RPF/martian posture,
  `accept_local` and forwarding sysctls for the shared `xpf-usp1` device (r6 §3.5 item 4 retarget);
  unproven hook/zone ⇒ DROP-and-count. Kill: un-inventoried hook/zone on the q0 path.

Reasoning for Y-not-N: K2's kill targets the MECHANISM CHOICE. That choice (shared outlet + mark
isolation + VRF-enslaved refusal + no per-domain TUNs) is built, live-witnessed, and sound; every gap
above fails CLOSED (permit never opens; drops counted) and is specifiable without architectural change.
Per r6 §6's own rule, Y authorizes proceeding ON must-proves — the four unproven enforcement clauses
roll forward to P-MECH/G5 with kill conditions, exactly as §3.5 must-proves are meant to work. Killing
the r6 deliverable after S4/S5 merged and witnesses went green, over specifiable must-proves, would
discard a conforming foundation to no safety benefit.

### §1.6 K2 statement (plain)

K2 (r6 §9.2: "N/refusal on §6 item 5 or 6 is a PLAN-KILL for this r6 deliverable") is NOT triggered by
this amendment (§1.4 Y; §1.5 Y-with-identity). It triggers if and only if:

1. The owner answers N (or refuses) on item #5 or #6 in-thread (§9.1 procedure); or
2. The owner rejects the D5a `D_usp1` identity (that rejection IS an item-#6 N per §6's own precondition
   rule); or
3. Any must-prove M1–M4 (or K-M5a, §5.4) FAILS without a narrowed, owner-authorized scope cut
   (e.g. V1 refuses PBR coexistence by config gate instead of proving M1 — a scope cut, not a kill;
   silent non-coverage is never an option).

Separate P-MECH gate (NOT K2): the owner MUST choose D12a Option A (explicit stateless-only scope cut)
or authorize/provide Option B's full INPUT session atomicity proof before S9.5 can implement or claim
broad INPUT permits. Refusal to authorize A, or failure to prove B, is a P-MECH PLAN-KILL even though
S12.5 #5/#6 remain Y. No silent fallback to "accept without session" is allowed.

On K2 trigger: the r6 deliverable (S4-authorization + this P-MECH amendment built on it) is PLAN-KILLED;
§1.7 lists exactly what a re-plan needs. No silent fallback to r5 TUN/VRF, no TAP/L2 revival, no
"capture-only permit" (r6 §6 + K6). This design proceeds through G1/G4 and the conditional G3/G5
mechanism only as a reviewable owner-decision record; it is not an implementation authorization until
D12a is resolved.

### §1.7 Re-plan needs (kill-boundary content, included complete though not triggered)

If K2 triggers, a newly authorized re-plan + hostile review (r6 §6 procedure) needs, at minimum:

1. A replacement re-entry/outlet mechanism (r5 per-domain TUN/VRF + policy-routing, TAP/L2, or a new
   domain mechanism) with its own S12.5 re-sign text, must-prove list, and threat-model delta.
2. A tunnel→zone derivation for THAT mechanism (inputs, authority, fail-closed rules) — §1.1–§1.2 do not
   transfer automatically (they assume the shared-outlet + census-permit foundation).
3. Re-validation of S4/S5 on the new foundation (permit/epoch/lease/provenance pieces may survive; q0
   outlet, fence conjunction, and witness joins are mechanism-specific).
4. Re-answers to §9.1 Q2–Q4 as affected (S3 spike authorization stands for the fence+divert coexistence
   facts already measured; T22/coupling economics re-bind to the new outlet).
5. P-MECH G1/G3/G4 re-grounded on the new path (Go hook sites, worker entry, deny taxonomy transfer
   structurally but re-pin to new call sites).

6. An explicit D12a owner record choosing Option A (and the exact stateless protocol/scope) or Option B
   (two-resource session prepare/finalize, rollback, and accepted-without-session kill boundary). Under
   Option A, every stateful INPUT miss remains E37 DROP; only proven Option B can permit stateful INPUT.

### §1.8 Alternatives rejected (re-sign)

- Strict-N on #6 ("as written certifies oracle/overlap as PRESENT, which is false, hence N → K2 now"):
  REJECTED. Misreads r6 §6's Y semantics (Y = proceed on must-proves, not certify completion);
  retroactive kill cannot "block S4" (S4 merged); every gap fails closed and is specifiable in P-MECH.
  The honest core of strict-N is preserved instead: §1.5 states plainly that bare-Y would be false, and
  §1.6 makes must-prove failure a K2 trigger.
- Bare-Y on #6 ("implicit Y from S4/S5 dispatch suffices; no identity record needed"): REJECTED. Would
  leave §6's explicit precondition ("identity MUST be written before Y") permanently unsatisfied and the
  oracle/overlap gaps unowned. This amendment exists to close exactly that.
- Deferring Q1 again (ship P-MECH, answer re-sign later): REJECTED. G2's owner-block is THE reason
  Step-0 stopped; P-MECH without a zone-derivation authority decision re-invents the deferred semantics.
  This amendment IS the deferred answer (Step-0 unblock option 1).

---

## §2 G1: evaluator API

### §2.1 Architecture: three layers, one policy engine

**D6.** Zone evaluation on the S5 path is THREE layers with ONE policy engine (the existing AF_XDP worker
pipeline — NO second firewall engine):

1. Go PRE-GATE (advisory early-drop + attribution): `ZoneEvaluator` hook in `submitEligible`, consulted
   AFTER origin validation, BEFORE lease minting. Fail-closed, cheap, synchronous. It NEVER permits —
   it can only DROP-early or PASS-TO-RUST (Rust remains authoritative). Divergence (Go-pass + Rust-refuse)
   is counted, never an error.
2. Rust WORKER-PIPELINE ADJUDICATION (authoritative): socket-admitted frames travel dedicated per-worker
   bounded ingress queues (pool-slot descriptors, NOT `WorkerCommand` variants, NOT per-packet `Vec<u8>`
   on the control queue) into the NORMAL worker pipeline via a new IPsec-inner entry that builds the
   owned frame (`build_logical_ingress_packet` path) and runs the EXISTING stage order (§3). FORWARD
   permits (with NAT mutation applied in-slab) proceed to q0; INPUT permits follow the no-mutation,
   no-q0 `CompletionInputReady` → supervisor-commit path (§2.5); deny terminalizes.
3. Rust `allows()` FINAL GUARD (authoritative lease/epoch): UNCHANGED semantics — permit/queue epochs +
   tombstones (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:381-394`), checked at admission AND immediately
   before the FORWARD TUN write or the INPUT terminal completion (`decide_pre_write`, `:395-414`;
   `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:1434-1437`). It guards LEASE/EPOCH only, never policy. No zone lookup is added to
   `allows()` (separation: policy verdicts flow through the worker pipeline; `allows()` stays the small
   lock-free authority it was designed to be — `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:250-256`).

Data flow: `receiveQueue` → `Enqueue` (provenance) → per-flow queue → `submitEligible` → [Go pre-gate] →
lease → `SubmitAdjudicated` → socket `admit` (shape/origin/epoch gates, UNCHANGED + §2.5 additions) →
owner-worker ingress queue → worker adjudication → verdict queue →
[FORWARD permit → `tx_delegated` enqueue → q0 write → `CompletionWritten` → held original `VerdictDrop`] /
[INPUT permit → no product-NAT mutation and no q0 → `CompletionInputReady` → supervisor
`commitValidatedVerdict`/`InputPermitCommitter` → held original `VerdictAccept`] / [deny → refuse +
completion + event]. The held NFQUEUE original is terminalized ONLY via the relevant authority: a
successful FORWARD q0 copy drops the held original, while INPUT ACCEPT is issued by the supervisor
commit adapter, never by the generic pipeline sink. The per-flow head remains blocked until this
InputCommitter returns, so a second INPUT miss cannot race the first result.

### §2.2 Go hook: signature, call sites, config, contract

**D7 (hook signature).** New file-adjacent interface in `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue` (beside `LeaseMinter`,
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:42-51`):

```go
// ZoneDecision is the Go pre-gate outcome. Pass means "no Go-side reason to
// refuse; Rust adjudicates authoritatively". It is NOT a permit.
type ZoneDecision uint8
const (
    ZoneInvalid ZoneDecision = iota // zero is never a permit
    ZonePass                         // explicit nonzero pass; Rust remains authoritative
    ZoneDrop                         // explicit fail-closed refusal
)

// ZoneReason is closed and survives the pre-gate boundary; callers MUST NOT
// infer a reason from a boolean or from an error string.
type ZoneReason uint8
const (
    ZoneReasonInvalid ZoneReason = iota // zero is never a valid result
    ZoneReasonZoned
    ZoneReasonUnzoned
    ZoneReasonAmbiguous
    ZoneReasonStaleGeneration
    ZoneReasonUnknownGeneration
    ZoneReasonLookupError
    ZoneReasonEvaluatorUnavailable
    ZoneReasonVersionSkew
)

type ZoneResolution struct {
    ZoneID uint16
    IfID   uint32
    Reason ZoneReason // Zoned means ZoneID and IfID are authoritative and non-zero
}

type ZoneEvaluation struct {
    Decision ZoneDecision
    ZoneID   uint16
    IfID     uint32
    Reason   ZoneReason
}

// ZoneSnapshotRef is the daemon-published per-generation zone authority the
// pre-gate reads: the §1.1 if_id→zone map + config/fib generations + permit state.
// Implemented by the daemon (S4 wiring); read-only to the pipeline.
type ZoneSnapshotRef interface {
    // ResolveSTN returns a typed result. It MUST return a non-Zoned reason for
    // UNZONED, AMBIGUOUS, stale/unknown generation, lookup, or version failure.
    ResolveSTN(stn string) ZoneResolution
    // Generations returns the (config, fib) generations this snapshot was built under.
    Generations() (configGen uint64, fibGen uint32)
    // Current reports whether this snapshot is still the live generation.
    Current() bool
}

// ZoneEvaluator is the Go-side zone pre-gate. Implementations MUST be
// synchronous, bounded-time, and non-blocking (no I/O, no locks held across
// calls); they read an immutable snapshot reference.
type ZoneEvaluator interface {
    Evaluate(origin CaptureOrigin, snap ZoneSnapshotRef) ZoneEvaluation
}
```

`ZoneEvaluation.Reason` is carried into `resolveRefusal` and the witness; the
pipeline never reconstructs UNZONED vs AMBIGUOUS vs stale from a collapsed `ok`
or an error string. `ZoneReasonZoned` is the only reason compatible with
`ZonePass`, and a pass MUST carry non-zero `ZoneID` and `IfID`; any missing or
inconsistent value is `ZoneReasonVersionSkew` + DROP. The submitted
`AdjudicatedFrame` and D11 descriptor copy these values immutably for Rust D14.
The all-zero value (`ZoneDecision==ZoneInvalid`, `ZoneReason==ZoneReasonInvalid`, `ZoneID==0`, or
`IfID==0`) is itself invalid and MUST resolve to DROP; it is never treated as an implicit "unknown but
allowed" or as a default-zone result.

**D8 (call sites).**

- PRIMARY: `submitEligible`
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:529-638`), AFTER the
  family/bridge gate (`:542-548`; S9.1 changes the current predicate so bridge and unsupported hooks
  reject, while inet `{forward,input}` continue) and BEFORE `p.lease(frame)` (`:549`). Rationale: origin is
  registry-validated by then (`Enqueue`, `:312-334`); refusing before lease minting avoids minting authority
  for frames that can never be admitted, keeps `Adjudicated` witness semantics ("lease minted" = passed
  all Go gates), and preserves per-flow head blocking (refused head → `resolveRefusal(reason)`, like lease
  failure `:550-553`). The typed `ZoneReason` is recorded at this boundary.
- SECONDARY (attribution only): `receiveQueue`
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go:211-246`).
  Plumb the queue's tunnel association (`captureQueue` already carries `Tunnel`/`VRF`/`Generation`,
  `:31-36`) into `CaptureFrame` as ADVISORY attribution when building the frame (`:231`), so drops that
  happen before/during registry validation (provenance mismatch, classify failure) can be attributed to
  a tunnel in counters/events. Advisory ≠ authority: the registry remains the sole authority; the
  advisory is never consulted for any verdict. (No mismatch check exists to write — advisory and registry
  derive from the same daemon staging; divergence would indicate memory corruption, not a checkable
  condition. Do NOT invent a comparison.)
- EXPLICITLY NOT called: `Enqueue` (provenance gate stays purely structural — zone needs validated
  origin, which `Enqueue` itself establishes), `MintLease` (lease mints PERMIT/EPOCH authority, never
  policy), any hot-loop polling path (evaluator runs once per eligible head, like `lease`).

**D9 (config + nil contract).** `CapturePipelineConfig`
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:147-161`) gains
`ZoneEvaluator ZoneEvaluator` + `ZoneSnapshot ZoneSnapshotRef` (atomic-pointer-swapped per generation by
the daemon; pipeline holds the reference, never mutates). It also gains a REQUIRED enforcing
`InputPermitCommitter` (§2.5); this is the only path allowed to NF_ACCEPT an inet/input original.
Fail-closed nil contract (mirrors `ErrNoLeaseMinter`/`ErrNoSubmitter`, `:166-167`):

- `ZoneEvaluator == nil`, `ZoneSnapshot == nil`, or `!snap.Current()` in ENFORCING → `ZoneDrop` with
  typed `ZoneReasonEvaluatorUnavailable` or `ZoneReasonStaleGeneration`, counted
  (`zone_gate_unavailable_total`/`zone_gate_stale_total`), never submitted.
- `InputPermitCommitter == nil` in ENFORCING → no inet/input frame can pass the pre-gate; the pipeline
  returns `ZoneReasonEvaluatorUnavailable`/`ErrNoInputCommitter` and terminal-DROPs. The generic
  `CapturePipelineConfig.Sink` fallback (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:275-281`) is DROP-safe but MUST NEVER be used to
  ACCEPT an input permit.
- In SHADOW phase → evaluator still RUNS (divergence counting per r5 §4.6); nil/stale/typed lookup
  doubt counts `shadow_unavailable` (r5 §4.6 failure table: evaluator-unavailable joins worker-dead/
  socket-loss in the kernel/...-unavailable class — observation preserved via ACCEPT-with-divergence for
  post-read failures, unavailable-counted for pre-read/unavailable authority), verdict stays ACCEPT per
  shadow semantics. Shadow MUST NOT silently become enforcing.

**D10 (Go error/deny contract).** `Evaluate` returns a `ZoneEvaluation` with a closed
`ZoneReason`: `ZoneDrop` + `ZoneReasonUnzoned`, `ZoneReasonAmbiguous`, `ZoneReasonStaleGeneration`,
`ZoneReasonUnknownGeneration`, `ZoneReasonLookupError`, or `ZoneReasonVersionSkew` for the corresponding
known/doubt states; only `ZonePass` + `ZoneReasonZoned` submits. `resolveRefusal(frame, reason)` records
the exact reason in `PipelineStats` and the bounded witness label (§4.3–§4.4); no later inference is
allowed. An impossible pass/reason pair is `ZoneReasonVersionSkew` + DROP. `Evaluate` MUST NOT block,
MUST NOT consult the network, and MUST complete in bounded microseconds (same discipline as `lease`,
`:640-655`).

### §2.3 Rust transport: dedicated per-worker ingress queues (NOT WorkerCommand packets)

**D11.** IPsec-inner frames reach workers over NEW dedicated per-worker bounded MPSC ingress queues
carrying POOL-SLOT DESCRIPTORS. Rationale (r5 §4.3 contract: "Double-buffered in-flight ≥ 2 batches;
bounded worker→capture verdict queue; capture thread never blocks; Heap: pooled slabs, no hot-path
allocation; batch rows carry (slot, len, tunnel key, flow key, queue-epoch, phase epoch …)"):

- Descriptor (Rust-internal, never on a socket): `{slab_id, len, tunnel_if_id, stn_ifindex, flow_tag,
  advisory_zone_id, advisory_if_id, permit_epoch, queue_number, queue_epoch, snapshot_generation,
  config_generation, fib_generation, phase_epoch, request_ids (1, or N for a completed fragment group —
  §3.6), flags}`. Immutable once enqueued (origin immutability mirrors `CaptureOrigin` registry
  semantics, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/origin.go:26-35`).
- Pool: Rust-side slab pool (PooledSlab, sized ≥ 2× in-flight batches + verdict depth per r5 §4.3).
  Socket recv writes DIRECTLY into an acquired slab (no per-packet `Vec` alloc on the Rust hot path; the
  Go-side copy at `Recv` + socket transfer is the unavoidable cross-process copy, priced in S7).
  Ownership transfers socket-server → worker → q0-writer → pool-release. Release happens exactly once on
  every terminal outcome (Written/Refused/Uncertain all release; write-started holds through definitive
  outcome — same hold discipline as `ReinjectLease`, r6 §3.2 step 3).
- Per-worker bounded queue (cap: named const `IPSEC_INNER_QUEUE_DEPTH`, sized with S7; full →
  DROP-and-count + `ipsec_inner_worker_queue_full_total`, socket-server never blocks — r5 "capture thread
  never blocks", r5:240-242).
- Owner routing: `flow_tag` (FNV-1a of `FlowKey`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/reinject_socket.go:524-527`) → stable hash mod LIVE
  worker set. Same flow → same worker → per-worker FIFO preserves per-flow order (r5 §4.3 "per-flow FIFO,
  with the same per-flow ordering lock as its sole sequencer" — the worker's ingress queue IS that lock
  for this path, joining `ReinjectCore.flow_order`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:865-869`, as the
  cross-worker sequencer record). Worker-set changes arrive as CONTROL (D12); in-flight descriptors
  under a retired set → stale → DROP-and-count, never misrouted.
- Bounded poll budget: each worker drains ≤ `IPSEC_INNER_DRAIN_BUDGET` descriptors per poll pass
  (r5 §4.4 "batches-per-poll-cycle fairness bound"), accounted against the same drain-budget discipline
  as `WORKER_COMMAND_DRAIN_BUDGET < MAX_PENDING_WORKER_COMMANDS`
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/worker_queue.rs:591`). Fairness vs AF_XDP RX: the IPsec-inner slice is a bounded FRACTION of the
  poll budget so neither physical ingress nor diverted ingress can starve the other; the fraction is a
  named const priced by T22/S7 (not a hardcoded ratio in this design).
- Bounded verdict queue back (worker → `ReinjectCore`): `{request_ids, verdict: Permit{mutation_applied,
  commit_mode: ForwardQ0|InputReady, provisional: Option<ProvisionalStateHandle>} |
  Deny{stage, reason, policy_id}, snapshot_generation, event_flags}`. `InputReady` is NOT terminal; it
  carries a handle only if D12a Option B is owner-authorized and its two-resource proof is present. Under
  candidate Option A, every INPUT miss is stateless and `provisional` is `None`: no session, BPF
  flow-cache, HA, or stateful-counter publication.
- `ProvisionalStateHandle` is a typed, opaque Rust-owned record:
  `{owner_worker, owner_generation, token, session_refs, nat_undo}`. `session_refs` is a bounded set of
  newly installed forward/reverse entries; `nat_undo` is the bounded release/revert token for every
  mutation in the permit branch. The owner worker is the sole authority that can consume the handle:
  q0 `CompletionWritten` sends exactly one `CommitProvisional(handle)`, while refusal/uncertain/stale/
  MTU/rate/queue failure sends exactly one `RollbackProvisional(handle)`. Existing-hit permits with no
  new state carry `None`. Go transports the opaque handle/result but cannot mutate or finalize it.
- Bounded, try-or-drop: verdict-loss fails closed via the existing `ackDeadline` (5ms) →
  uncertain → DROP path (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:259-260`, `:690-697`) — the loss window is bounded and terminal
  state is always DROP. Verdict-queue-full is counted (`ipsec_inner_verdict_queue_full_total`) + alarmed,
  never silent.

**D12a (INPUT session boundary; explicit unresolved scope decision).** Existing INPUT session HITS are
consulted and revalidated, but stored NAT metadata that would rewrite/translate is E36 DROP. Broad
stateful INPUT parity (TCP/UDP/SCTP, application/ALG, and any flow that requires a new session) still
requires an atomic relationship between NF_ACCEPT and worker-owned session publication; the
`InputPermitCommitter` alone does NOT provide that relationship.

- **Option A — candidate authorized scope cut, NOT assumed here:** allow only explicitly stateless
  protocols (ICMP/ICMPv6 and flowless L3 shapes whose existing worker path does not require a session).
  A local INPUT MISS then performs full screen/host-inbound/policy evaluation but MUST NOT install or
  publish a session, BPF flow-cache entry, HA record, or stateful policy counter. TCP/UDP/SCTP,
  application/ALG, and any `strict_syn_check_drops_new_flow`-ineligible miss are DROP + E37. This is
  fail-closed but is not general INPUT permit parity; the owner must authorize it before S9.5.
- **Option B — required for full INPUT parity:** design and prove a bounded two-phase session
  prepare/finalize protocol with an accepted-without-session residual explicitly owned and kill-gated.
  That protocol is not present in this amendment; it MUST NOT be invented implicitly by treating
  `CompletionInputReady` as a session commit.

Until the owner records A or B, P-MECH cannot claim broad INPUT permits. This is an explicit scope
decision/PLAN-KILL boundary, not a silent performance optimization; G5 carries the live-proof and kill
condition. If A is authorized, every subsequent stateless miss is fully re-adjudicated and the per-flow
head remains blocked until supervisor commit; if B is selected, the slice remains blocked until its
two-resource proof passes.

**D12 (WorkerCommand stays control-only).** NO packet-bearing `WorkerCommand` variant (the existing enum
— `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/types/runtime.rs:542-613` — carries session-control ops only: upserts, deletes, PPTP assoc,
shaped TX, vacate, RG ops, queries; per-packet `Vec<u8>` + reply slots there would violate r5's pooled
descriptor/batching/fairness contract and risk starving control operations behind data). `WorkerCommand`
carries ONLY: config/fib generation publication, worker-set/fence/drain commands, and the existing
control family. (This also answers delta C38's STALE-UNCERTAIN 17-field binding note: the P-MECH
descriptor's field set is specified HERE (D11), not inferred from `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/worker_queue.rs`.)

### §2.4 Rust entry: owned-frame + generations + async verdict

**D13 (entry function).** New IPsec-inner entry on the worker (file-adjacent to the GRE/WG decap entries;
exact file owned by G5 slice): build the owned frame via the SHARED `build_logical_ingress_packet`
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:79-186`) — NOT a copy (a divergent second copy of a
synthesize/rebind/reparse path is precisely the #7176 C179-001 defect class the module header warns
against, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:9-18`). Parameters:

- `inner_packet` = slab bytes (reassembled datagram for fragments, §3.6); `inner_family`/`inner_eth_proto`
  from the Go classification (re-validated in Rust — Go classification is advisory, Rust parse is
  authoritative; mismatch → doubt → DROP).
- `logical_ifindex` = the TUNNEL's logical ifindex (xfrmi, from origin — NEVER outer/physical;
  #7167 invariant 2, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:53-56`).
- `outer_ecn`: `None` — the outer ESP header is consumed by kernel XFRM before NFQUEUE capture, so no
  outer ECN is observable; the RFC 6040 combine is SKIPPED with reason (not faked). Record as an
  explicit, reviewed exception to the combine (spoofing outer-CE would be a concealment primitive;
  `None` skips per `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:98-99`). Alternative-rejected: thirteen other ECN postures all
  require an outer header that does not exist at this capture point.
- `ecn_illegal_drops`: a NEW per-protocol static (`ipsec_inner_ecn_illegal_drops`) — "Per-protocol so the
  drop is attributable" (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:63-65`); sharing GRE's counter would misattribute.
- `meta_flags`: a NEW `IPSEC_INNER_INGRESS_FLAG` ("whatever GRE passes is not an answer for another
  protocol", `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:66-68`).
- `config_generation` / `fib_generation`: the values CAPTURED AT STAGING for the frame's queue generation
  (Go stamps from the authorizing snapshot, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go:561-562`; carried on the socket wire, D15),
  satisfying #7167 invariant 5 ("a packet decrypted under an old attachment must never be evaluated under
  a replacement's zone/VRF identity" — `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:30-40`). The worker compares against its LIVE
  generations; mismatch → STALE → DROP-and-count (never evaluate old-attachment bytes under new identity).
  Fabricating generations (`0`, fresh-read) is FORBIDDEN by the same invariant (a fabricated generation
  "always looks current" and violates fencing SILENTLY).
- `rx_queue_index`: the divert queue number (attribution; keeps per-queue accounting exact).

The entry returns the adjudication SYNCHRONOUSLY within the worker's poll (it runs the §3 stage order
inline — the worker IS the pipeline) and posts the verdict to the D11 verdict queue (async relative to
the socket server). "Asynchronous" = decoupled from socket admit, NOT deferred within the worker.

**D14 (zone gate inside the entry, before pipeline).** After owned-frame build, BEFORE any stage (§3):
resolve `ingress_zone` EXACTLY as `build_logical_ingress_packet` does (`ifindex_to_zone_id[logical]`,
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:145-149`) and additionally require: zone ≠ 0, zone == the stamped Go-advisory
`ZoneID`, and the Rust-derived immutable `if_id` == stamped Go-advisory `IfID` (all non-zero). A
missing/zero/mismatched zone or if_id is doubt ⇒ DROP; generation must be fresh (D13). The Rust gate
recomputes from its snapshot, so a Go/Rust tunnel-zone or if_id disagreement cannot pass. Rationale for
an EXPLICIT pre-pipeline gate instead of relying on policy default-Deny: (a) attribution (which tunnel,
why — policy default-Deny sees only zone 0); (b) `default_action` is SNAPSHOT-CONFIGURED and can be
`Permit` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:2005-2009`) — relying on policy for unzoned tunnels fails OPEN under default-permit;
(c) the INPUT path's `host_inbound_admits(0)` takes the `None => true` global-zone admit arm
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/forwarding/unzoned_tunnel_host_inbound_9941_tests.rs:8-12`) — zone 0 must never reach it. This gate is the
`#6682`-class guard for the divert path (cf. `UNZONED_INGRESS_DENIED`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:174-198` + #9989
unattributed logging).

### §2.5 Socket `admit` additions + `allows()` (unchanged core)

**D15.** `admit_with_class_owner` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:801-874`) keeps its existing gates (flags,
dry-run, shutdown, lease shape, `origin.wire_valid()`, BRIDGE-ONLY refusal; validated inet
`{forward,input}` origins are eligible, then `allows()`, duplicate, capacity) and gains, IN ORDER after
the `allows()` epoch check: (a) generation-capture presence (config/fib generations non-zero and
wire-valid — missing ⇒ new `ADMIT_NO_GENERATION`); (b) slab availability (pool exhausted ⇒ `ADMIT_FULL`
— an existing code, no new variant needed); (c) fragment-group shape validity (§3.6 ⇒
`ADMIT_BAD_LEASE` on malformed grouping). New `ADMIT_*` reason codes extend the u8 enum
(`ADMIT_OK..ADMIT_NON_DRY_RUN = 0..7`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:33-40`): `ADMIT_NO_ZONE = 8`
(zone gate D14 refuse), `ADMIT_ZONE_CONTESTED = 9`, `ADMIT_STALE_CONFIG = 10`,
`ADMIT_NO_GENERATION = 11` — additive, wire-compatible (reason is a u8; Go's `decodeAdmissions` maps
unknown codes to refusal, and Go MUST treat any unknown code as refusal).

The old generic input-hook refusal is narrowed, not deleted: `{inet,input}` is admitted to the worker;
`{bridge,input}` (and every non-inet/unsupported hook) remains a structural refusal and never reaches
policy. For `{inet,input}`, the worker MUST NOT call `submit_adjudicated_frame`, set the q0 mark, or emit
`CompletionWritten`. After the final `allows()` check it emits a NEW non-terminal
`CompletionInputReady` carrying request/permit/queue epochs, `snapshot_generation`, zero `BytesWritten`,
and an optional session-ref set ONLY under the owner-authorized full-session option D12a. Under the
candidate stateless scope cut, the set is empty. `CompletionInputReady` means "worker prepared; supervisor
commit still required", not NFQUEUE ACCEPT.

`InputPermitCommitter` is a REQUIRED enforcing adapter:

```go
type InputPermitCommit struct {
    RequestID, PermitEpoch, QueueEpoch, SnapshotGeneration uint64
    QueueNumber uint16
    PacketID uint32
}
type InputCommitResult uint8
const (
    InputCommitInvalid   InputCommitResult = iota // zero is never authorization
    InputCommitAccepted                            // explicit nonzero: supervisor sink issued NF_ACCEPT
    InputCommitDropped                             // explicit nonzero: supervisor sink issued NF_DROP
    InputCommitUncertain                           // explicit nonzero: sink result unknown; never retry
)
type InputPermitCommitter interface {
    CommitInputAccept(InputPermitCommit) (InputCommitResult, error)
}
```

The adapter and resolver MUST reject `InputCommitInvalid`, any unknown result, `Accepted` with a non-nil
error, and `Dropped`/`Uncertain` with a result/error combination that claims no terminal attempt; all
such combinations are E35/uncertain → DROP. The daemon adapter registers each capture queue as the
matching immutable supervisor gate kind (`ipsecGateInput` for inet/input), builds `ipsecPacketRef`, and
calls `ipsecSupervisor.commitValidatedVerdict` with the live permit record. That existing method holds
`commitLease.RLock` from full permit/gate/queue/snapshot validation through the packet sink syscall
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_reinject_supervisor.go:602-656`);
the adapter MUST NOT use the generic `CapturePipelineConfig.Sink` fallback
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:275-281`) for ACCEPT.
On supervisor refusal the helper itself emits exactly one DROP; on sink error it returns
`InputCommitUncertain`. `submitGate` only orders against pipeline cancellation; it is not an S4 authority
check.

The Go completion resolver accepts `CompletionInputReady` only for exact `{inet,input}`, zero bytes, and
matching request/permit/queue/snapshot identities. It invokes the committer: `InputCommitAccepted` means
the supervisor already NF_ACCEPTed; the resolver records the terminal result and keeps the per-flow head
blocked until this return. `InputCommitDropped` records one DROP (without a second sink call);
`InputCommitUncertain` records uncertain/drop accounting and never retries. A malformed/late completion is
E35 and DROP. Existing `CompletionAccepted`/`CompletionWouldReinject` remain advisory/nonterminal for
FORWARD and are NOT aliases for `CompletionInputReady`.

`allows()` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:381-394`) is UNCHANGED (permit/queue epochs + tombstones + open).
It remains the final pre-write guard for FORWARD and the final pre-`CompletionInputReady` guard for INPUT
via `decide_pre_write` (`:395-414`). NO policy/zone/session predicate enters `allows()` — D6 separation.
The candidate stateless scope does not claim broad INPUT session parity; the full-session requirement and
kill/scope decision are D12a/G5.

### §2.6 Doubt definition + fail-closed matrices

**D16 (doubt).** DOUBT = any state where the evaluator cannot PROVE the frame is currently authorized.
Exhaustive arms (each maps to a §4 taxonomy row — no arm maps to permit):

1. Unknown zone (Rust `ifindex_to_zone_id` miss → 0 at D14 gate).
2. UNZONED tunnel (Go map: no claim) / AMBIGUOUS tunnel (Go map: multi-claim) — §1.1.3.
3. Stale generation (captured config/fib/permit/queue generation ≠ live; includes worker-set change
   in-flight, rotation mid-flight, permit CLOSING/CLOSED).
4. Lookup error (registry miss, snapshot read error, session-table lock poison/unavailable — on poison,
   the uniform #1807 policy applies: committed state intact, fast path restored, counted recovery; the
   AFFECTED frame still DROPS, only the table recovers).
5. Timeout (verdict not returned within `ackDeadline`; socket round-trip timeout).
6. Policy snapshot unavailable (Rust `ForwardingState` not installed for the frame's generation;
   `PolicyState` build failure for the generation).
7. Ambiguous match (session alias candidates > 1, §3.5; flow-owner transfer race lost, r5 §4.4).
8. Version skew (socket protocol version ≠ `ProtocolVersion` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go:327`); snapshot older than
   `MinProtocol*` floors; Go/Rust wire-codec mismatch — exact-equality gates, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go:12-15`).
9. Revoked/closing authority (permit not OPEN; queue-scope cancel applied; contested-ifindex removal
   observed, #7509).

Fail-closed matrices:

| Condition | Enforcing | Shadow (r5 §4.6 retained) |
|---|---|---|
| Known zone-policy DENY | DROP + `policy_deny` + `PolicyDeny` event | ACCEPT + divergence count (adjudication ran) |
| Any doubt arm (D16.1–9) | DROP + arm-specific counter + event | post-read doubt: ACCEPT + divergence; authority-unavailable doubt (nil evaluator, no snapshot, worker-set down): `shadow_unavailable` (joins r5 §4.6 worker-dead/socket-loss class) |
| Verdict-queue/socket loss | uncertain → DROP, no retry (§1.4 row) | `shadow_unavailable` |
| Go pre-gate Drop | DROP, never submitted (`zone_gate_*` counters) | divergence-counted ACCEPT (pre-gate still runs) |

Reject (policy `Reject` action) ≡ Deny + `policy_reject_as_deny_total` in V1 (SILENT drop; no TCP
RST/ICMP synthesis — §3.4 rationale). No condition in either matrix maps to permit-on-error.
### §2.7 Alternatives rejected (G1)

- A1 (full evaluation on the socket thread calling worker stage functions): REJECTED. Creates a second
  firewall engine (parallel session, NAT, screen, and policy application outside worker-owned state), forks
  worker-local session visibility, and contradicts the GRE/WG owned-frame precedent
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:3-15`: plaintext is built FOR the normal worker pipeline). Adopted instead: D6/D13
  worker-pipeline adjudication (review steer, grounded in r5 §4.3–§4.4 + #7167).
- A2 (packet-bearing `WorkerCommand` variant with `Vec<u8>` + reply slots): REJECTED. Violates r5 §4.3
  pooled-slab/batching/fairness contract; per-packet allocation on the hot path; risks starving control
  operations (session sync, vacate, RG ops) behind data. Adopted instead: D11 dedicated per-worker
  ingress queues + pool-slot ownership transfer + bounded poll budget; `WorkerCommand` stays control-only
  (review steer, grounded in r5 §4.3 + `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/worker_queue.rs` bounds).
- A3 (Go hook performs policy evaluation via sync RPC to Rust per frame): REJECTED. Hot-path RPC latency
  + failure-mode explosion on the bounded handoff (r5: capture never blocks); duplicates the submit path
  it precedes. Adopted: D7 pre-gate (cheap local checks only) + async worker adjudication.
- A4 (zone lookup inside `allows()`): REJECTED. `allows()` is the small lock-free lease/epoch authority
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:250-256`); policy lookups would widen its contract, its locking, and its
  failure modes. Separation kept: epochs in `allows()`, policy in the worker pipeline.
- A5 (rely on policy default-Deny for unzoned/zero-zone instead of D14 explicit gate): REJECTED.
  `default_action` can be snapshot-configured `Permit` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:2005-2009`); INPUT `host_inbound_admits(0)`
  takes the global admit arm; attribution would be lost. Explicit gate REQUIRED.
- A6 (Go `Enqueue` as the hook site): REJECTED. `Enqueue` establishes validated origin; the hook needs it
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:312-334`). `submitEligible` post-family/hook-gate, pre-lease is the single correct site.

---

## §3 G3: session, NAT, and screen integration order on the IPsec-inner path

### §3.1 Governing rule

**D17.** The owned IPsec-inner frame runs the WORKER PIPELINE'S EXISTING stage order BY CONSTRUCTION
(D13 entry feeds the same code GRE/WG-owned frames traverse). G3 therefore specifies (a) the order as
observed (pinned, not re-derived), (b) per-stage CONSULT-vs-SKIP for owned IPsec-inner frames with
reasons, (c) conflict precedence, (d) the fragments/session-identity rules that differ from native by
necessity. NOTHING in the worker order is reordered for P-MECH; skips are enumerated exhaustively in §3.2
(any stage not listed there is CONSULTED).

Pinned order (forward/miss path, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs`): screen (`stage_screen_check` — FIRST, every
packet hit or miss, `:446`, `:4335-4336`) → session resolve (`resolve_flow_session_decision…`, `:752-753`)
→ [HIT: established fast path (§3.4)] / [MISS: syn-cookie stage (`:1720`) → static-DNAT → DNAT
(Junos order, `:1774-1789`: "static NAT → destination NAT → route → …") → NPTv6/NAT64 as configured →
route/disposition → LocalDelivery: host-inbound admission (`:2625`) → `junos-host` policy (`:2734`) /
transit: zone-pair policy `evaluate_policy_result_with_icmp` (`:2962`, post-DNAT tuple `:2021-2064`) →
permit: SNAT alloc (`:3207`, permit-branch ONLY — "a denied flow never consumes a pool port", `:1953-1956`;
`source_nat_decision_for_flow` in `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/nat_exception.rs`) → session install (forward+reverse, `:3307-3422`;
refusal ⇒ SNAT rollback + DROP, `:3319-3323`) → NAT counters at committed install (`:3501-3504`)].

INPUT has a deliberately distinct terminal path. The capture rule is an NFNETLINK input chain at
priority `-175` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nftables/ipsec_divert.go:17-20,193-198`),
so the held bytes are post-kernel-prerouting but PRE-product/userspace-NAT. Its order is screen → session
resolve → product NAT decision-only checks (static-DNAT/DNAT/NPTv6/NAT64; any matching rewrite or
cross-family translation is E36 DROP) → route/disposition check (MUST be `LocalDelivery`) →
host-inbound admission/lo0 → `junos-host` policy → **session boundary D12a**. A permit emits
`CompletionInputReady` only after the terminal epoch guard (§2.5), and then the supervisor adapter
NF_ACCEPTs the same bytes. Under candidate Option A, only stateless ICMP/ICMPv6/flowless shapes may
reach this permit; stateful misses take E37. Option B is required for broad stateful INPUT parity.
Deny at ANY stage ⇒ terminal DROP + §4 deny path; later stages skipped (deny-overrides, §3.3).

### §3.2 Consult-vs-skip table (owned IPsec-inner frames; both hooks unless noted)

| Worker stage | FORWARD | INPUT | Reason |
|---|---|---|---|
| `stage_screen_check` (from-zone screen) | CONSULT | CONSULT | Stateless per-packet protections; skipping creates an unscreened ingress class. Zone resolves from tunnel logical ifindex (same as GRE/WG). |
| Session lookup (shared + worker-local scopes) | CONSULT | CONSULT | Single session universe (§3.5); no second table. |
| Established-hit revalidation (#8356 policy, #3706 host, #7212 filter, `session_hit_authority` arrival-zone) | CONSULT | CONSULT; inspect stored `decision.nat`/NAT64 metadata before any `CompletionInputReady`; rewrite/translation ⇒ E36 DROP | Hit authority BY CONSTRUCTION; arrival-zone rule needs no P-MECH case (owned meta carries tunnel logical ifindex — cf. `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/session_hit_authority.rs:37-39` for GRE/WG). INPUT cannot accept an established translated session unchanged. |
| Syn-cookie-on-miss stage | CONSULT | CONSULT | Same SYN-flood posture as native. |
| static-DNAT → DNAT (+ counter split) | CONSULT | CONSULT (decision-only: no-match/identity continues; any product rewrite ⇒ E36 DROP) | Junos pre-routing order for FORWARD; INPUT cannot replace an NF_ACCEPT payload, so a matching product rewrite is fail-closed. |
| NPTv6 inbound / NAT64 match | CONSULT | CONSULT (decision-only: no-match/identity continues; any prefix/cross-family translation ⇒ E36 DROP) | FORWARD applies configured stages; INPUT never applies a product translation to held bytes. |
| Route/disposition resolve (userspace FIB) | CONSULT | CONSULT — after the no-mutation proof, MUST resolve `LocalDelivery` | FORWARD determines egress + to-zone; INPUT validates that the held pre-product-NAT tuple remains host-bound. NoRoute or INPUT→transit ⇒ DOUBT ⇒ DROP. |
| Zone-pair policy (`evaluate_policy_result_with_icmp`, post-DNAT tuple, live ICMP type/code) | CONSULT | N/A (host path instead) | THE zone enforcement (from = tunnel zone D14, to = `egress_zone_id` unambiguous map — NEVER `ifindex_to_zone_id` for to-zone, #6722/`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/forwarding/mod.rs:235-250`). |
| Host-inbound admission + lo0 gate | N/A | CONSULT | Mirrors physical LocalDelivery miss (`:2625`); kernel `xpf_hostinbound` chain re-judges post-ACCEPT at the input hook — AND-composition (both must permit), documented layering, no conflict. |
| `junos-host` policy (`junos_host_local_policy`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/host_inbound_policy.rs:254`) | N/A | CONSULT | Runs AFTER host-inbound admission ("Junos order", `:1567-1570`); deny/reject ⇒ DROP + policy-deny RT_FLOW (`:1570`). |
| SNAT / static-SNAT / NPTv6-outbound alloc (permit branch only) | CONSULT | SKIP | FORWARD: Junos post-policy source translation; applied to q0 bytes pre-write (r6 §3.2 step 1 "PERMIT-with-mutation"). INPUT: NO SNAT on local-delivery path (precedent `:2870-2874`); NF_ACCEPT releases the held bytes unchanged. |
| Session install (forward+reverse, policy-counter stamp, generation stamp) | CONSULT (permit REQUIRES install; install-fail ⇒ DROP) | D12a boundary: Option A SKIP new-session install and publish (stateless only); Option B REQUIRED full-session prepare/finalize, not yet designed | Forward-permit without install would orphan return traffic; FORWARD install is part of permit (precedent: refusal ⇒ rollback + DROP, `:3319-3323`). INPUT broad parity is a kill-gated open requirement. |
| NAT rule counters (DNAT+SNAT independent Arcs, once each at committed install) | CONSULT | SKIP for no-match/identity; E36 mutation cases are not committed | FORWARD counters are committed exactly once; INPUT never mutates or double-counts product NAT. |
| BPF session-map publish + flow-cache seed | CONSULT | Option A SKIP; Option B REQUIRED before claiming broad parity | Return traffic (LAN→tunnel via workers/XDP) needs the session visible; P-MECH does not silently publish INPUT state before NF_ACCEPT. |
| Kernel-conntrack mirror (`publish_conntrack`) | SKIP | SKIP | Mirror covers AF_XDP sessions ONLY (r6-delta C44). Kernel sees re-injected traffic as fresh flows in the shared-device zone per M4 inventory; mirroring P-MECH sessions would double-represent them. M4 kill condition guards zone conflict. |
| GRE/WG/IPsec-passthrough DECAP stages (`stage_native_gre_decap`, `stage_wg_decap`, `stage_ipsec_passthrough_check`) | SKIP | SKIP | Outer already consumed by kernel XFRM; re-decap would misparse inner as outer. |
| Link-layer classify (`stage_link_layer_classify`) | SKIP | SKIP | Synthetic Ethernet is trusted-constructed (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:83-85`); L2 validation meaningless. |
| AF_XDP RX/TX descriptor handling | SKIP (slab/queue transport instead, D11) | SKIP | No UMEM descriptors on this path by construction. |
| Slow-path reinject chokepoint (`maybe_reinject_slow_path…`) | SKIP (verdicts route to q0 writer via D11 verdict queue) | SKIP | Different outlet; the q0 writer (not the slow-path chokepoint) owns the commit. |
| MissingNeighbor / neighbor-seed paths | SKIP | SKIP | P-MECH never forwards natively; kernel resolves post-TUN neighbors. Pending-neighbor buffering does not apply (held packet is NFQUEUE-held, not worker-held). |
| Flowless/non-first-fragment L3-only arms (`:4516`, `:4918`, `:5073`) | CONSULT (as applicable) | CONSULT | Fragments are adjudicated as DATAGRAMS (§3.6); the flowless arms apply only to genuinely flowless shapes that reach the worker (defense in depth, same code). |
| ALG / embedded-ICMP / PPTP-assoc / filter-log / policer stages | CONSULT | CONSULT | Consult-by-construction: no P-MECH exception exists in those stages; any future stage added to the worker pipeline applies to owned frames automatically (closed-world default = consult). |

INPUT safety invariant: NFQUEUE `VerdictAccept` has no replacement-payload API. Therefore the worker MUST evaluate
the held bytes as they exist at the input hook (post-kernel-prerouting, pre-product/userspace-NAT), MUST run
product NAT matching decision-only, and MUST DROP-and-count E36 whenever a configured product rule would
rewrite or cross-family translate. The policy tuple is treated as post-product-NAT only in the proven
no-match/identity case. A permitted INPUT frame is never sent to q0. The route resolver MUST return
`LocalDelivery`; an INPUT result of `ForwardCandidate`, `FabricRedirect`, or any other non-local disposition
is `INPUT→transit route-changed` and maps to E20, DROP, and its dedicated counter. This is the symmetric
guard to FORWARD→LocalDelivery; it prevents a local-hook permit from becoming an unproven transit injection.

FORWARD-hook + firewall-local dst (kernel routed to FORWARD but FIB now says local) ⇒ route-changed
DROP-and-count; INPUT-hook + non-local disposition (FIB now says transit/fabric) ⇒ route-changed
DROP-and-count. Never ACCEPT a forward-held packet as input; never re-inject host-bound to TUN; never
ACCEPT an input-held packet whose disposition is transit.

### §3.3 Conflict precedence

**D18.** (a) Deny-overrides-permit at every stage: the FIRST deny terminalizes; later stages never run
(count the FIRST deny only, to keep exactly-once deny accounting — mirrors single-terminal-verdict
discipline). (b) Session-hit vs policy-change: established revalidation tears down on narrowed policy
(#8356/#3706/#7212 — CONSULTED, §3.2); a hit never re-permits what current policy denies. (c) NAT vs
policy: policy evaluates the POST-DNAT tuple (`:2021-2064`); SNAT never precedes policy (permit-gated
alloc). (d) Screen vs session: screen runs even on session HITS (`:4335-4336`) — session never exempts
screening. (e) Foreign-hit vs owner-entry: `session_hit_authority` + `foreign_hit_verdict` UNCHANGED
(judge arrival zone's policy for THIS packet; no in-place install overwrite — the documented anti-hijack
rule, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/session_hit_authority.rs:78-84`). (f) Go pre-gate vs Rust verdict: Rust authoritative; Go-pass +
Rust-refuse = counted divergence, terminal DROP (never Go-override).
q0 failure cleanup (FORWARD): session/NAT allocations are PROVISIONAL until the single q0
`CompletionWritten` commit. A q0 refusal, stale fence, MTU/rate/queue refusal, or ACK timeout invokes
exactly-once rollback for the worker-owned `session_refs` and NAT undo records; no BPF/flow-cache/HA
publication occurs before that commit. If a later terminal failure observes already-published state, the
same terminal owner closes/rolls it back exactly once before releasing the held NFQUEUE originals. INPUT
Option A publishes no session state; Option B MUST specify the equivalent prepare/finalize rollback before
it can claim stateful parity. A rollback failure is E10/E17-class DROP plus its existing counter, never
an ACCEPT or retry.

### §3.4 Established-hit path + Reject posture

**D19.** Session HIT on an owned frame follows the worker established path verbatim: policy hit-counter
re-count (`:830-899`, incl. the #3706 LocalDelivery exception), #8356/#7212 re-derivations, host-inbound +
junos-host teardown re-checks for LocalDelivery (`:1373-1585`), NAT application from the entry (`decision.nat`
— `rewrite_src`/`rewrite_dst` applied to q0 bytes for FORWARD-permit), flow-cache accounting. No P-MECH
fast-path fork.

**D20 (Reject ≡ Deny in V1).** Policy `Reject` (and zone `tcp-rst`-on-deny) maps to SILENT DROP-and-count
+ `policy_reject_as_deny_total` (+ `tcp_rst_suppressed_total` where the zone configures `tcp-rst`). The
physical path synthesizes TCP RST / ICMP unreachable toward the source (`:4089-4093`, `deny_reply_and_emit`,
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:176`) — but that reply EMITS via worker TX with proven egress, while a P-MECH reject
would have to originate tunnel-bound (XFRM-encrypted, kernel-routed) traffic from userspace with NO
owned-egress proof. Silent-drop is the fail-closed direction; Junos-reject parity is an explicit V1 scope
cut with a follow-up (G5), NOT a silent equivalence (distinct counters + this paragraph). Flowless deny
stays silent per precedent (`:4516-4518`).

### §3.5 Session identity: tunnel discriminator (no aliasing)

**D21.** Same-zone cross-tunnel inner flows MUST NOT share session entries (r5 §2: "multi-tunnel
isolated"; overlapping RFC1918 behind branches is the common enterprise shape, not a corner):

- New `TunnelDiscriminator` class `Ipsec(if_id: u32)` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/discriminator.rs` — the enum + wire codec
  + `reverse_direction_discriminator` gain one arm each; wire tag in a fresh `<< 32` band beside
  `WIRE_PPTP_TAG`, never reusing GRE/PPTP tag space — #7188 decision-6 discipline:
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/discriminator.rs:10-25,132-136`).
- Derived from IMMUTABLE tunnel identity: the config-stable XFRM `if_id` (D1), NOT outer peer IP, NOT
  underlay/physical ifindex, NOT live kernel ifindex (node-local — would alias across HA peers per #6928:
  "a node-local number names a different NIC on the peer"). Go passes STN (advisory); Rust derives if_id
  from the origin + snapshot (authoritative); un-derivable (unknown STN, if_id 0) ⇒ doubt ⇒ DROP (D16.7).
- Carried in FORWARD and REVERSE keys. Forward lookup (owned frame, second+ packet): key WITH `Ipsec(A)`
  ⇒ hits ONLY A's entry; native spoof (same 5-tuple, `None`) ⇒ different key ⇒ MISS ⇒ native miss path
  (no aliasing at all — strictly better than zone-authority fallback). Cross-tunnel B packet ⇒ different
  key ⇒ B's own miss path ⇒ own policy/session/NAT (no eviction — `install_with_protocol_with_origin`
  replaces only SAME-key entries, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/install.rs`).
- Reply resolution: the reply (LAN→tunnel, native parse, `None`) resolves through the EXISTING
  discriminator-aware reverse/alias index machinery (`lookup_session_across_scopes`, reverse + alias
  indexes — the same machinery GRE replies traverse). Contract: 0 candidates ⇒ MISS (native handling);
  exactly 1 ⇒ that entry; >1 (genuinely ambiguous overlapping no-NAT replies — unanswerable from the
  packet, the same ambiguity kernel FIB resolves by pick) ⇒ AMBIGUOUS ⇒ doubt ⇒ DROP-and-count
  (`session_alias_ambiguous_total`) + event. Deterministic-pick REJECTED (silent misdelivery risk);
  with SNAT the replies differ (separate per-install allocations ⇒ distinct external tuples) and resolve
  uniquely — the common SNAT case just works.
- Snapshot-build duplicate-if_id check: two VPNs yielding one if_id is commit-REJECTED (#2933) on the
  strict path, but the tolerant-load path downgrades to warning — so the daemon snapshot builder MUST
  detect duplicate if_id across admitted VPNs and mark those tunnels unadjudicable (AMBIGUOUS ⇒ DROP +
  alarm). Cheap, deterministic, defense in depth.
- Generations separate ATTACHMENTS (D13 fencing); the discriminator separates TUNNELS. Both required:
  delete/recreate under one name keeps if_id (stable) but advances generations (stale sessions fenced).
- `SessionOrigin` for P-MECH installs: `ForwardFlow` (transit) / `LocalMiss` (host-bound) — NO new origin.
  Rationale: post-admission semantics are identical to ordinary flows (counting, HA sync, close-announce,
  expiry); a new origin would fork every origin-switch with zero behavioral benefit. HA failover then
  works via existing session sync (standby imports as ESTABLISHED, `upsert_synced_with_origin`).

Alternatives rejected: (i) accept GRE/WG-identical same-zone sharing (document + warn): REJECTED — r5
requires multi-tunnel isolation and branch-overlap is common; sharing merges SNAT allocations/TCP state
across tenants (review steer; mechanism: `SessionKey` discriminator axis `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/session_hit_authority.rs:5-7`
exists FOR this class). (ii) Overload `routing_domain` with tunnel identity: REJECTED — corrupts FIB
resolution semantics (domain selects the route table). (iii) Separate P-MECH session table: REJECTED —
second session universe; return-path fork; defeats worker replication ("every worker holds a copy",
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/types/runtime.rs:571-572`).

### §3.6 Fragments: one adjudication per datagram, per-fragment q0 writes

**D22.** Go `FragPool` keeps the r5 §6.8 contract (v6 overlap⇒whole-datagram DROP, exact-duplicate tuple,
atomic-domain split, v4 first-wins retained set, ≤128×64KiB caps, tombstones — `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/fragpool.go`, all live).
On completion, Go submits ONE adjudication unit (all fragment bytes + N request_ids/leases, one
datagram-id) to the owner worker (D11 queue). The worker concatenates (single alloc on the miss path ONLY
— documented, priced in S7), builds ONE owned frame, adjudicates ONCE (policy sees reassembled L4 —
"Reassembly: worker post-capture pre-policy", r5:423; "Non-first fragments never permit alone", r5:459),
then: permit ⇒ enqueue EACH fragment's ORIGINAL bytes to q0 (per-fragment NAT per the non-first-fragment
address-only-L3-rewrite precedent, `:4297-4300`), each under its own request_id ⇒ N completions ⇒ Go
terminalizes each held original; deny ⇒ N refusals. "Never a merged super-datagram" on the wire (r5:431):
q0 carries original fragments, kernel reassembles downstream. Reassembly-owner flow-affinity (r5 §4.4:
flow-owner record + per-flow-lock transfer) is satisfied BY the owner-worker routing (D11): the datagram
adjudicates on its flow's owner worker; no cross-worker transfer exists on this path.

### §3.7 Counter/deny-event points (per stage; Rust worker side)

Screen deny → `screen_drops` + `ScreenPacketInfo` alarm event (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/event_emit.rs:333`); session-install
refusal → `create_drops` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/install.rs:100-104`) + DROP; policy deny → `telemetry.dbg.policy_deny` +
`PolicyDeny` RT_FLOW (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/event_emit.rs:138`); NAT failure → `record_source_nat_failure` + DROP; host-inbound
deny → `host_inbound_denied_packets` + `emit_host_inbound_deny` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/host_inbound_policy.rs:170`);
junos-host deny → policy-deny RT_FLOW (`:1570`); zone-gate deny → NEW `zone_gate_*` counters + `PolicyDeny`
with `UNATTRIBUTED_POLICY_ID` (§4.1 — the #9989 unattributed pattern, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:195-198`); generation
fence → `zone_gate_stale_total`; alias-ambiguous → `session_alias_ambiguous_total`. Go side: §4.3–§4.4.

---

## §4 G4: deny path

### §4.1 Event types (reuse first; one justified new reason family)

**D23.** NO new event KIND. All P-MECH denies reuse the existing dataplane event codec
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/event_stream/codec`, `DataplaneEventKind::PolicyDeny` — `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/event_stream/codec/decode.rs:50-52`):

- Policy-denied (FORWARD zone-pair, INPUT junos-host): `PolicyDeny` with the DENY rule's `policy_id`
  (existing `emit_policy_deny_event`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/event_emit.rs:138`; flowless/inapplicable-L4 keeps the
  `SkippedFragDeny` attribution discipline, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:3763-3769`).
- Pre-policy denies (zone gate D14, generation fence, alias-ambiguous, session-install refusal,
  NAT failure): `PolicyDeny` with `policy_id = UNATTRIBUTED_POLICY_ID` (0 — `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:172`) + a
  bounded reason string (`tunnel-zone-unzoned`, `-ambiguous`, `-stale`, `session-alias-ambiguous`,
  `session-install-refused`, `source-nat-failure`, …). Precedent: #9989/#6682 unzoned-ingress denies
  "LOG as `unattributed` rather than `default-policy`" with the dedicated counter as the aggregate-cause
  signal (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:195-198`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy_tests.rs:7770-7812`).
- Host-inbound denies: existing `emit_host_inbound_deny` tuple-rich event (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/host_inbound_policy.rs:170`).
- Screen denies: existing screen alarm event (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/event_emit.rs:333`).
- Go-side pre-submit refusals: NO dataplane event (Go has no event-stream producer on this path);
  counters + Prometheus witness labels only (§4.3–§4.4). The AUTHORITATIVE deny event always emits in
  Rust where evaluation happens — EXCEPT Go pre-gate refusals, which never reach Rust by design (their
  evidence is the Go counter + labels; double-emission would double-count).

### §4.2 Emission points

Rust (worker thread, at the refusing stage — same call sites as native denies): zone gate (D14, in the
D13 entry before pipeline); screen (`stage_screen_check` deny arm); session-install refusal (install
call site); policy (`deny_reply_and_emit` — `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:176` — with reply SUPPRESSED for P-MECH,
V1 scope D20: logs DENY truthfully per the suppressed-reject tests, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/reject_reply_tests.rs:1551+`);
NAT failure (`record_source_nat_failure` site); host-inbound/junos-host (existing emit sites, §3.2);
alias-ambiguous (reverse-lookup ambiguity site, §3.5). Rate-limiting: the existing generated-error /
event-stream backpressure discipline applies unchanged (no P-MECH exemption; event loss under pressure
is counted by the stream, never silent).

Go (`submitEligible` refusal arms + `Enqueue` provenance arms): counters only (§4.3), exported via the
witness (§4.4). No log-per-deny (rate-bounded telemetry only, r5 H1 — a log line per drop is a DoS
amplifier; the existing code already avoids it).

### §4.3 Counters

Rust (all `u64`, per-worker or shared per existing convention; every name here is REQUIRED — a stage
without its counter fails review):

- `zone_gate_unzoned_total`, `zone_gate_ambiguous_total`, `zone_gate_stale_total`,
  `zone_gate_no_generation_total` (D14/D16 arms).
- `ipsec_inner_input_routed_transit_total`, `ipsec_inner_input_accept_errors_total` (INPUT disposition
  mismatch and terminal-ACCEPT/completion protocol failures; E20/E35).
- `ipsec_inner_input_stateful_without_session_total` (E37; Option A scope-cut refusal for stateful INPUT
  misses until Option B is proven).
- `session_alias_ambiguous_total` (§3.5 multi-candidate replies).
- `policy_reject_as_deny_total`, `tcp_rst_suppressed_total` (D20 V1 scope markers).
- Reused (existing, no rename): `policy_deny`, per-rule hit counters + `default_counter`
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs`), `UNZONED_INGRESS_DENIED`, `host_inbound_denied_packets`, `screen_drops`,
  `create_drops`, NAT per-rule counters + `snat_packets`/`dnat_packets`, `adjudicated_refused`/
  class counters (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:448-451`), `epoch_rejects`, `mtu_dropped_packets`,
  `rate_limited_packets`, `queue_full_packets` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs`).

Go (`PipelineStats`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:171-198`, additive fields): `ZoneGateDrops`, `ZoneGateUnavailable`,
`ZoneDivergences` (Go-pass/Rust-refuse), `PolicyDenies` (completions `CompletionDenied` — decode exists,
`:883`), `AliasAmbiguous` (completions carrying the alias reason — new outcome code or reason-mapped
refusal; G5 pins the wire bit). Existing reused: `ProvenanceMismatches`, `L2Unsupported`,
`OverlapRefusals`, `FragmentDrops`, `AdmissionsRefused`, `Refused`, `Uncertain`, `Stale`, `Cancelled`,
`Timeouts`, `LateCompletions`, `HandoffRefusals`, `ShadowDivergences`. Every new field MUST be exported
in the witness (§4.4) — an unexported counter is operator-invisible and fails review.

### §4.4 Metrics + witness join

Extend the 2a witness pattern (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/api/metrics_ipsec_capture_10478.go:14-60`): the actor snapshot
(`IpsecCapturePipelineStatus`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go:53-65`) gains the §4.3 Go fields; the
collector emits them as `CounterValue` with the EXISTING label set (`runID`, `generation`,
`permitEpoch` — `:22-25`) PLUS a bounded `reason` label for deny families (zone_unzoned,
zone_ambiguous, zone_stale, policy_deny, alias_ambiguous, … — closed enum, no high-cardinality values:
NEVER raw STN/tunnel names as label values — tunnel attribution belongs in EVENTS (Rust side, tuple-rich)
and logs, not in metric cardinality). Rust `s5_reinject` stats block gains the §4.3 Rust counters under
the existing `(run_id, generation, permit_epoch)` join. Pipeline-stats/metrics naming follows the
`ipsecCapture<Name>Total` + `xpf_ipsec_capture_<name>_total` convention of the existing collector.

### §4.5 Error taxonomy (EVERY failure → DROP-and-count; no silent drops, no permit-on-error)

| # | Failure | Detector | Terminal | Counter | Event |
|---|---|---|---|---|---|
| E1 | Tunnel UNZONED | Go pre-gate / Rust D14 gate | DROP (never submitted / refused) | `zone_gate_unzoned_total` (+Go `ZoneGateDrops`) | `PolicyDeny`/unattributed (Rust only) |
| E2 | Tunnel AMBIGUOUS (multi-claim if_id) | Snapshot build (mark) + gates | DROP | `zone_gate_ambiguous_total` | `PolicyDeny`/unattributed + alarm |
| E3 | if_id underivable (unknown STN / 0) | Wiring (staging refuse) + gates | DROP | `zone_gate_unzoned_total` (same family) | `PolicyDeny`/unattributed |
| E4 | Stale config/fib/permit/queue generation | D14 fence + `allows()` + Go `Current()` | DROP | `zone_gate_stale_total` / `Stale` | `PolicyDeny`/unattributed |
| E5 | Missing generations on wire | Socket admit (D15a) | Refuse (never queued) | `zone_gate_no_generation_total` | — (pre-admission; Go `AdmissionsRefused`) |
| E6 | Zone/Go-advisory mismatch | D14 cross-check | DROP | `ZoneDivergences` | `PolicyDeny`/unattributed |
| E7 | Screen deny | `stage_screen_check` | DROP | `screen_drops` | Screen alarm |
| E8 | Session lookup error (poison/unavailable) | Lookup (uniform #1807 recovery) | DROP (frame); table recovers | existing session-error counter | — + recovery counter |
| E9 | Session alias ambiguous (multi-candidate reply) | Reverse/alias resolution (§3.5) | DROP | `session_alias_ambiguous_total` | `PolicyDeny`/unattributed |
| E10 | Session install refused (cap 131072/worker, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/install.rs:1072-1073`) | Install | DROP + SNAT rollback | `create_drops` | — (counter is the signal, precedent `:100-104`) |
| E11 | Zone-pair policy DENY | `evaluate_policy_*` | DROP (silent) | `policy_deny` + rule/default counter | `PolicyDeny` (rule-attributed) |
| E12 | Zone-pair policy REJECT | `evaluate_policy_*` | DROP (silent V1, D20) | `policy_reject_as_deny_total` + rule counter | `PolicyDeny` (REJECT-truthful? NO — logs DENY per suppressed-reject precedent `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/reject_reply_tests.rs:1551+`) |
| E13 | `tcp-rst`-on-deny (zone screen option) | Deny arm | DROP (no RST V1, D20) | `tcp_rst_suppressed_total` | `PolicyDeny` |
| E14 | junos-host policy deny/reject | `junos_host_local_policy` | DROP | `policy_deny` + rule counter | policy-deny RT_FLOW (`:1570`) |
| E15 | Host-inbound deny | Host-inbound gate | DROP (silent, session torn down `:1457-1461`) | `host_inbound_denied_packets` | `emit_host_inbound_deny` |
| E16 | Static/DNAT match error / scope failure | Pre-routing NAT | DROP | existing NAT-error counters | — |
| E17 | SNAT alloc failure (pool exhausted, non-first-frag gate `:3026`, NPTv6 refuse `:3182`) | Permit-branch NAT | DROP + release partial | `record_source_nat_failure` counters | — |
| E18 | NAT64/NPTv6 translation failure | Translation | DROP | existing translation counters | — |
| E19 | Route NoRoute (userspace FIB) | Route resolve (§3.2) | DROP (doubt) | `ipsec_inner_noroute_total` | `PolicyDeny`/unattributed |
| E20 | Hook/disposition mismatch (FORWARD resolves `LocalDelivery`; INPUT resolves transit/`FabricRedirect`/non-local) | Route/disposition check (§3.2) | DROP (doubt; never switch hooks) | `ipsec_inner_routed_local_total` / `ipsec_inner_input_routed_transit_total` | `PolicyDeny`/unattributed |
| E21 | Inner-prefix overlap admitted (M3 violation observed) | M3 admission/commit checks | Tunnel DOWN + DROP | `nfq_reentry_unsupported_domain_total` (r6 §3.5 item 6 name — REUSED, not reinvented) | `PolicyDeny`/unattributed + alarm |
| E22 | Other-VRF/RG/FIB packet at admission | M3 per-packet check | DROP | `nfq_reentry_unsupported_domain_total` | `PolicyDeny`/unattributed |
| E23 | Worker ingress queue full | D11 enqueue (try-or-drop) | DROP | `ipsec_inner_worker_queue_full_total` | — + alarm |
| E24 | Verdict queue full / verdict lost | D11 verdict path / `ackDeadline` | Uncertain → DROP, no retry | `ipsec_inner_verdict_queue_full_total` / `Uncertain`+`Timeouts` | — (terminal accounting is the record) |
| E25 | Slab pool exhausted | Socket admit (D15b) | Refuse | `ipsec_inner_slab_exhausted_total` | — (Go `AdmissionsRefused`) |
| E26 | Lease/permit/epoch failure (closed, stale, mismatch, echo-mismatch) | `MintLease`/`allows()`/echo check | Refuse/Uncertain → DROP | `Stale`/`Cancelled`/`Uncertain`/`AdmissionsRefused` (existing) | — (existing terminal accounting) |
| E27 | Submitter unavailable / socket down | `submitEligible` / socket client | Refuse/Uncertain → DROP | `Refused`/`Uncertain` (existing `ErrNoSubmitter`) | — |
| E28 | Evaluator unavailable (nil/stale snapshot) | Go pre-gate (D9) | DROP (enforcing) / shadow-unavailable (shadow) | `ZoneGateUnavailable` / `shadow_unavailable` | — (witness labels) |
| E29 | FORWARD q0 MTU/queue/rate failure OR INPUT terminal-ACCEPT sink failure | `submit_adjudicated_frame` / Go `finishFrame` | Refuse/uncertain → DROP | `mtu_dropped_packets`/`queue_full_packets`/`rate_limited_packets` / `ipsec_inner_input_accept_errors_total` | — + terminal accounting |
| E30 | Fragment-group malformed (bad grouping, reassembly-contract violation) | Go `FragPool` / admit D15c | DROP (whole datagram + held set) | `FragmentDrops`/`OverlapRefusals` (existing) | — |
| E31 | Provenance mismatch / unregistered queue | `Enqueue` | DROP (never q0) | `ProvenanceMismatches` (existing) | — |
| E32 | Non-inet or unsupported hook at submit (bridge is quarantine; inet/input is supported) | `submitEligible` family/hook gate | DROP | `L2Unsupported` (existing) | — |
| E33 | Version skew (socket/snapshot/protocol) | Exact-equality gates (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go:12-15`) | Refuse snapshot / DROP | existing version-gate counters | — + operator-visible abort |
| E34 | Owner-worker down / worker-set retired in-flight | Router + fence | DROP (never misroute) | `ipsec_inner_worker_retired_total` | — + alarm |
| E35 | Invalid/mis-scoped `CompletionInputReady` (non-inet/input, nonzero bytes, or terminal identity mismatch) | Go completion resolver / worker outcome codec | DROP/uncertain | `ipsec_inner_input_accept_errors_total` + `Uncertain` | — + alarm |
| E36 | INPUT product NAT would rewrite or cross-family translate (NF_ACCEPT cannot replace payload) | Decision-only static-DNAT/DNAT/NPTv6/NAT64 consult | DROP (before policy/route) | `ipsec_inner_input_nat_mutation_unsupported_total` | `PolicyDeny`/unattributed |
| E37 | INPUT stateful miss outside authorized D12a Option A, or `strict_syn_check_drops_new_flow`/session-required shape | D12a session boundary | DROP before NF_ACCEPT | `ipsec_inner_input_stateful_without_session_total` | `PolicyDeny`/unattributed |

Coverage claim: arms D16.1–9 ⊂ {E1–E37}; every `resolveRefusal`/`resolveUncertain`/terminal-DROP call site
in `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go` maps to exactly one row; every Rust refuse path maps to exactly one row. The G5 slice
MUST include a mechanical audit (grep every `VerdictDrop`/refuse/uncertain emission on the S5 path against
this table; unmapped emission = review failure). No row maps to permit, ACCEPT (except shadow-divergence
ACCEPT per §2.6 matrix), retry, or silence. `CompletionInputReady` is non-terminal and is covered by
E35 on any malformed or mis-scoped use; E36 covers product-NAT mutation; E37 covers stateful INPUT
misses when Option A is the only authorized scope.

### §4.6 Alternatives rejected (G4)

- New `TunnelZoneDeny` event kind: REJECTED. New kinds fork every consumer (codec, decoders, dashboards,
  retention). The #9989 unattributed pattern (`UNATTRIBUTED_POLICY_ID` + dedicated counters) exists FOR
  pre-policy denies — reuse it.
- Go-side dataplane deny events: REJECTED. Go has no event-stream producer here; counters + witness
  labels are the established Go evidence surface (2a pattern). Authoritative events emit once, in Rust.
- Log-per-deny: REJECTED. Rate-bounded telemetry only (r5 H1); per-drop logging is a DoS amplifier.
- Merging limitation counters into one generic drop count: REJECTED. r5 N5 (r5:645-651) explicitly pins
  per-cause counters ("fails if its named counter is absent, merged into a generic drop count, or not
  emitted per generation") — the same anti-merge rule governs §4.3 names.

---

## §5 G5: owning slice plan

### §5.1 Slice definition (closes "no owning slice for §4.4")

**D24.** P-MECH is owned as ONE slice (no sub-slice split — the Go hook, Rust entry, and deny taxonomy
are one reviewable unit with a single live-proof gate), sequenced AFTER S4/S5 (landed) and INDEPENDENT of
O-*/V-FLIP/D-SYNC (zero file overlap: product-only, harness untouched — remainder-map dispatch constraint).
It REPLACES the missing r5 §12.4 bullet for §4.4: "S9 (P-MECH) zone mechanism: evaluator hook +
worker-pipeline IPsec-inner entry + session, NAT, screen, and deny per this amendment; kill-gated on §5.4."

### §5.2 File list (absolute; M = modify, N = new)

Go:

- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go` — `ZoneEvaluator` +
  `ZoneSnapshotRef` + config fields + `submitEligible` call site (D7–D10) + `PipelineStats` fields (§4.3)
  + `ErrNoZoneEvaluator`.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go` —
  receive-time tunnel attribution (D8 secondary) + status snapshot fields (§4.4).
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go` —
  per-generation if_id→zone map build (§1.1) + config/fib generation capture at staging (D13) +
  duplicate-if_id detection (§3.5) + snapshot atomic publication (D9).
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/reinject_socket.go` — wire:
  generations + fragment-group descriptor on submit (D13/D15/§3.6); unknown admit-reason ⇒ refusal (D15).
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/api/metrics_ipsec_capture_10478.go` (+
  collector decls) — §4.4 witness extension + `reason` label.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go` — ONLY if
  snapshot lacks a stamp P-MECH needs (audit first; `Generation`/`FIBGeneration`/epochs all present —
  `:561-567`; a version bump needs the lockstep procedure, `:12-15`).

Rust (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/`):

- N `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/ipsec_inner.rs` (worker entry D13 + zone gate D14 + verdict post) + N `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/ipsec_inner_queue.rs`
  (D11 per-worker ingress queues + slab pool + verdict queue + poll-budget drain) — NEW files (no
  suitable existing owner; adjacent to `gre.rs`/`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/wg/decap.rs` precedent).
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs` — NOTHING (reuse as-is; the entry CALLS `build_logical_ingress_packet`).
  If the entry needs a param the struct lacks, extend `LogicalIngressParams` (all-fields-required
  discipline preserved — `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:26-40`).
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs` — admit additions (D15) + new `ADMIT_*` codes + verdict→(q0 enqueue |
  refuse) completion joins + §4.3 counters + `s5_reinject` stats export.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs` — `submit_adjudicated_frame` routes permit-verdicts to `tx_delegated` (existing enqueue
  body reused; the worker verdict REPLACES direct enqueue — the function splits into admit→dispatch and
  verdict→enqueue halves; single-writer + lease-hold disciplines unchanged).
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/discriminator.rs` + `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/key.rs` + wire codec — `Ipsec(if_id)` class (D21) + reverse arm
  + HA-wire tag + unknown-tag fail-closed import.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/*lookup*` — ambiguous-multi-candidate detection ⇒ DROP (D21 contract; seam named by G5).
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/worker/*` (poll loop) — D11 drain (bounded budget) + verdict post; `WorkerCommand` gains
  ONLY generation/worker-set control variants (D12).
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs` — NOTHING (evaluation reused; D20 Reject≡Deny handled at the P-MECH deny arm, not in
  policy). If truthful REJECT logging needs a flag, add a call-site param — never change default paths.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/event_stream` — NOTHING (existing kinds/reasons extended by string only, §4.1).

Tests (in-file + existing suites; no new harness): unit cells per §5.3; the G5 slice owns its cells +
affected-suite numbers; NO harness file (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/test/incus/*`) is
touched (O-*/V-FLIP own those).

### §5.3 Slice order (within P-MECH; each step reviewable, fail-closed at every intermediate)

1. S9.1 Go pre-gate + wiring (map build, staging capture, `submitEligible` site, stats, metrics) with
   Rust stubbed to refuse-all-new-codes (proves Go fail-closed standalone; live-proves denied-only).
2. S9.2 Rust transport (queues + pool + verdict path + admit codes) with worker entry stubbed to
   deny-all-with-reason (proves plumbing + taxonomy E23–E25/E34 standalone).
3. S9.3 Worker entry + zone gate + generation fence (D13–D14; proves E1–E6/E33 with datagram verdicts).
4. S9.4 Session discriminator + fragment datagram path (D21–D22; proves E9–E10/E30, alias matrix).
5. S9.5 Full stage consultation + NAT mutation + q0 join (D17–D20; proves E7/E11–E20 and FORWARD
   permitted flows). INPUT `CompletionInputReady`/supervisor commit is wired only after D12a Option A
   authorization or Option B's two-resource proof.
6. S9.6 Deny-path completion + taxonomy audit E1–E37 (§4.5 coverage proof) + metrics/witness join.
7. S9.7 Live-proof gate (§5.4) + M1–M4 must-prove evidence (or authorized scope cuts).

### §5.4 Validation bar (MUST all hold; any fail = slice kill or authorized scope cut, §1.6)

- Unit cells (fail-on-revert): zone map (zoned/unzoned/ambiguous/cross-spelling/duplicate-if_id/stale);
  Go hook (pass/drop/nil/stale/shadow-matrix); typed reason/zero-value refusal; admit codes (each new
  code + unknown-code-refusal); supervisor committer result matrix (invalid/unknown/accepted/dropped/
  uncertain + stale-after-lease and sink-failure); discriminator (forward separation, reverse
  unique/ambiguous/native-miss, wire round-trip, unknown-tag import refusal); fragments
  (overlap/first-wins/atomic/duplicate/tombstone + one-adjudication-N-writes); taxonomy (each E-row
  fires its counter once; no unmapped terminal emission — mechanical audit §4.5); generations
  (stale fence, fabricated-zero refusal); doubt arms D16.1–9 (each → DROP, never permit).
- Affected suites + reverse-deps with numbers (run at slice end; parent validates project-wide).
- THE live run (loss cluster, real SAs — MATCH-gated attestation): denied AND permitted FORWARD v4+v6
  decrypted-ingress flows with policy/session/counter/event evidence (FORWARD→q0→fence delivered
  witness). INPUT live evidence is conditional: only after D12a Option A authorization may the run
  claim permitted stateless ICMP/ICMPv6/flowless v4+v6 (`CompletionInputReady`→supervisor
  `InputPermitCommitter`→NF_ACCEPT, never q0); Option B is required before any stateful INPUT claim.
  Both hooks still cover each deny family at least once (zone-unzoned, zone-ambiguous, policy-deny,
  screen-deny, host-inbound-deny, alias-ambiguous (crafted overlap), stale-generation (rotation during
  flow), fragment-permit + fragment-deny), NAT-T + native, multiple tunnels (incl. same-zone overlap
  pair for D21 + M3 evidence), 8/16/32 scale spot.
- HA feasibility: RG-failover during P-MECH flows (standby imports `ForwardFlow`/`LocalMiss` via existing
  sync — D21; sessions survive per existing close-class/wheel semantics; capture runs primary-only per S4
  lifecycle). NOTE (honest): full split-brain/dual-active proof is out of V1 (r5 §12.6 residual 10 carries
  forward: "HA split-brain safety depends on RG fencing"). Kill: failover loses established P-MECH sessions
  that native sessions keep ⇒ scope cut (document) or kill (if worse than native).
- MTU feasibility: jumbo + 1500-degraded-TUN refusal cells (existing `MtuExceeded` machinery §1.4 row;
  P-MECH adds: NAT-growth re-check pre-q0-write — a NAT-mutated frame exceeding live TUN MTU ⇒ DROP, never
  fragment-on-q0 (no q0 fragmentation proof exists)). Kill: silent truncation or kernel-drop without counter
  on any MTU cell.
- Pricing feasibility (S7/T22): per-worker poll-budget fraction + slab-pool sizing priced on the loss
  cluster at the T22 mix (IMIX + jumbo, 8×4K bidir, 70/20/10, 5% frag, 1% host-bound, +20% overload-shed —
  r6 §8 retained); 80%/250µs kill polarity retained (K4); B-invariant kill phrasing retained (if the
  B-invariant portion alone busts T22, no B saves it — r5 §2). The 2×-bytes fragment command (§3.6) and
  per-datagram concat alloc are priced line items, not hidden costs. Kill: T22 miss on the loss cluster
  (K4 honors itself).
- M1–M4 evidence (or authorized scope cuts recorded in the sign-off, §1.5–§1.6). K-M5a: §3.5-item-2
  coupling proof-or-split cell (G1/T8) — owned by S4/S7 but REQUIRED before P-MECH's permitted-flow claims
  are valid under delegated load (a coupled q0 refusal under flood must be proven within overload-shed
  budget, else DROP-and-count the coupled class per §3.5 item 2).

### §5.5 Kill conditions (slice-level; supplement §1.6 K2)

- K-P1: any E-row unmappable or any terminal emission unmapped (§4.5 audit fails).
- K-P2: any doubt arm permits (D16 matrix violation) in any test or live cell.
- K-P3: live run cannot show the required denied evidence on BOTH hooks and permitted FORWARD v4+v6
  with joined evidence; permitted INPUT evidence is required only for owner-authorized Option A
  stateless shapes, while Option B is required before any stateful INPUT permit claim.
- K-P4: T22/K4 miss attributable to P-MECH path (poll budget, pool, concat, verdict latency).
- K-P5: M1–M4 unresolved AND no authorized scope cut (escalates to §1.6 K2.3).
- K-P6: HA failover regresses vs native session survival.
- K-P7: any new TUN, fence pinhole, VRF re-entry topology, AF_XDP-on-xfrmi, AF_PACKET, userspace ESP, or
  selector-as-policy appears in the slice (r6 §4 prohibitions — automatic kill, no re-plan within P-MECH).
- K-P8: owner does not authorize D12a Option A and no proven Option B exists, or any stateful INPUT
  miss is accepted without the required session atomicity; this is a P-MECH PLAN-KILL (not a silent
  stateless narrowing).

---

## §6 Threat-model delta vs r6 S1 (+ G6 accounting)

G6 accounting (parent steer): r5 §1 framing ("deliberately open", "forward with no policy/…", r5:46-53)
is STRUCK (r6 §1.1, r6-delta C04/C06/C17/C23/C46 FALSIFIED by #10302) and is cited NOWHERE normatively in
this design. The mechanism targets EXCLUSIVELY the r6 §1.1/§1.3 residual statement: fail-closed-drop +
(a) INPUT/host-bound incl. VRF-master bypass + (b) marked-`xpf-usp1` semantics + (c)
fail-closed-but-unadjudicated DROP (§1.3c is precisely what P-MECH converts to adjudicated verdicts).

Narrow delta INTRODUCED by this design (all else in r6 S1 stands unchanged):

1. (Conditional new stimulus) INPUT-hook ACCEPT verdicts: only D12a Option A (owner-authorized
   stateless ICMP/ICMPv6/flowless scope) or a future proven Option B may ACCEPT host-bound inner packets
   that today are divert-held-then-dropped (`L2Unsupported`). The bounded Option A threat change requires
   screen + session lookup (MISS must be an allowed stateless shape) + pre-product-NAT held-tuple
   validation + decision-only product NAT no-match/identity + LocalDelivery disposition + host-inbound
   admission + lo0 + junos-host policy (§3.2–§3.3) AND the kernel `xpf_hostinbound` chain re-judges
   post-ACCEPT (AND-composition). INPUT never q0-writes or performs a second NAT mutation; a matching
   product NAT rule is E36 DROP, and stateful misses are E37 DROP. `CompletionInputReady` is routed
   through the supervisor committer and releases the original held bytes only after its live check.
2. (Documented non-parity) Reject-silence (D20): V1 drops what Junos would RST/reject. Threat direction:
   silent-drop is strictly less informative to attackers than RST (no port-state oracle) — a hardening,
   not a weakening — but an OPERATOR-VISIBLE behavior cut (distinct counters) with a follow-up.
3. (Documented behavior) Session aliasing rule (D21): overlapping no-NAT replies that are genuinely
   ambiguous DROP (doubt) instead of kernel-FIB-pick. Threat direction: fail-closed; availability cost is
   operator-fixable (VRF separation) and M3-detected.
4. (No change) Residuals (b) and (c)'s fence/drop posture: untouched. FORWARD default remains fence-DROP
   for everything not explicitly adjudicated-permitted (r6 §1.3c last line honored verbatim).
5. (No change) #9646 local-address lifecycle, #7480 ordering, permit-all-outbound residual: untouched
   (out of P-MECH scope; r6 §1 notes carry forward).

Net: the design NARROWS every residual it touches and introduces no new permit class without a verdict +
evidence. No S1 rewrite is required — this §6 is the complete delta record.

---

## §A Grounding index (claims → master file:line or plan §)

Format: claim area → anchors. All code anchors verified at `1a6952b61` in this worktree; plan anchors
cite r6 (`/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md`) /
r5 (`/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md`) /
delta (`/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-delta.md`).

- Divert path today (leases all, no evaluator): `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go:211-246`
  (receive), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:147-161` (config sans evaluator), `:529-581` (submitEligible),
  `:193-197` (Adjudicated = lease minted), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:381-394`
  (`allows` epochs-only), `:801-874` (admit gates).
- Provenance + registry + Enqueue gate: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/origin.go:26-108`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:312-334`.
- Wiring (STN=BindInterface, if_id validation, live ifindex, 4-class keys): `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go:37-40,95-106,285-332`.
- Permit/census/VRF/outlet refusal: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_topology_owner_9506.go:184-243`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_reinject_supervisor.go:349-351` (Safe-gated OPEN), `:142-146` (permitRecord).
- Fence + mark + witness: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nftables/transit_barrier.go:22-43,227-254`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nftables/transit_barrier_counters.go:27` (readback), TC `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:35-41,183-187,282-283`.
- Lease/commit/ACK/cancel/timeouts: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:32-51,259-260,623-634,663-681,690-697,751+,880-885,928`;
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/reinject_socket.go:69,184-205`; `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:131-147,208-232,418-432,865-869`;
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:103-111,1195-1300,1434-1437`.
- Zone maps + strict gates + if_id: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/xfrmi.go:50-56,287-351`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/host_inbound_effective_view.go:101-154`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/zones.go:148`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/compiler_validate_strict_zones.go:213-240,274-314`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/compiler_ipsec_plaintext_warn.go:246-268`, `#4515/#2933/#5297/#5619/#6691` comments therein.
- Owned-frame + generations + zone-from-logical: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:3-18,24-73,79-186`
  (#7167 inv 2/5, #7167/#7176/#921/#8581 notes); callers `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/gre.rs:923`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/wg/decap.rs:214`.
- Zone maps (Rust) + contest/refusal + zero semantics: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/forwarding_build/interfaces.rs` (populate,
  `row_zone_id != 0` gate, #7509 removal), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/forwarding/mod.rs:223-251` (pair fn, xfrmi/MAC-less note),
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:3065` (nonzero gate), `:2005-2009` (default_action), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/forwarding/unzoned_tunnel_host_inbound_9941_tests.rs:8-12`
  (zone-0 global admit), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:174-198` + #9989 (UNATTRIBUTED).
- Policy entries + actions: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:125-135` (Permit/Deny/Reject, default Deny), `:2819-2870`
  (entries), `:2915-2973` (ICMP/L3-aware), `:3390+` (junos-host).
- Worker order + NAT + install + host path: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs` lines cited inline in §3.1–§3.2
  (`:446`, `:752-753`, `:1720-1789`, `:1862-1869`, `:1953-1956`, `:2021-2064`, `:2625-2766`, `:2870-2874`,
  `:2962`, `:3207-3323`, `:3495-3504`, `:4089-4093`, `:4297-4300`, `:4335-4336`, `:4516-4518`).
- Hit authority + foreign verdict: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/session_hit_authority.rs:5-113,139-167,183-190,259-326`.
- Sessions + discriminator + install + sync: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/key.rs` (5-tuple + `TunnelDiscriminator` + `routing_domain`),
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/discriminator.rs:8-25,132-136` (#7188 d6), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/entry.rs:83-92` (#4983 stamp),
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/install.rs:100-104,142-150` (cap + refusal), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/README.md:1071-1168` (origins, caps, sync),
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/types/runtime.rs:542-613` (WorkerCommand), `:571-572` (replication), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/worker_queue.rs:80,591-623` (bounds).
- Deny events/counters/metrics: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/event_emit.rs:138,230,333`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/host_inbound_policy.rs:170`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:176`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/event_stream/codec/decode.rs:50-52`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/api/metrics_ipsec_capture_10478.go:14-60`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go:53-65`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:171-198`.
- RPDB bands + FBF/PBR: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/routing/rules.go:64-90`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/routing/pbr_applied_7422.go:22-24`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/routing/fibimport.go:98-102`
  (usp0-resolves-in-main note), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/routing/README.md` band table.
- Plans: G1 (r5:262-289, r6:1967-1969-C36-unbuilt); G2 (r6:1446-1463 item 8, r6 §6 `:1734-1814`, §9.1 Q1
  `:1981-1983`, K2 `:2039-2041`); G3 (r5:280-289, r6:1081-1088, r6:235-239); G4 (r5:475-478, r5:645-651 N5,
  r5:684-686); G5 (r5:735-768 §12.4, no §4.4 bullet); G6 (r5:46-53 struck; r6:41-89 §1.1; r6:147-274
  §1.3–§1.4; delta C04/C06/C17/C23/C46); r6 §3.1–§3.2 (`:1050-1154`), §3.5 (`:1368-1463`), §4 prohibitions
  (`:1467-1502`), §8 retained (`:1879-1975`), §9 (`:1977-2056`); r5 §4.3–§4.4 (`:238-289`), §6 (`:401-493`),
  §12 (`:641-825`).

---

## §B Design-input review steers (adopted; grounded above, not taken on authority)

1. Worker-pipeline adjudication (not socket-thread mirrored evaluation): adopted as D6/D13 — grounded in
   r5 §4.3–§4.4 + `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:3-15` + #7167/#7176.
2. Dedicated per-worker data queues + pool slots + poll budget; `WorkerCommand` control-only: adopted as
   D11–D12 — grounded in r5 §4.3 + `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/worker_queue.rs` bounds + `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/types/runtime.rs:542-613`.
3. Tunnel discriminator in session keys (no aliasing): adopted as D21 — grounded in `SessionKey`
   (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/key.rs`) + `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/session_hit_authority.rs:5-7` + #7188/#6928 + r5 §2 multi-tunnel isolation.

*(End of P-MECH mechanism design. G1/G2/G4 mechanisms are specified; G3 INPUT session atomicity and
G5 implementation/live proof remain owner-gated. G6 is accounted in §6; §9.1 Q1 is answered in §1.4–§1.6;
kill conditions are in §1.6 + §5.4–§5.5; re-plan needs are in §1.7. Until D12a Option A is authorized
or Option B is proven, this document is a conditional design record and a P-MECH PLAN-KILL boundary,
not implementation authorization.)*
