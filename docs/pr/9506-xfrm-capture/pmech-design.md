# P-MECH mechanism design: fail-closed zone enforcement on the S5-diverted path (#9506)

- Status: CONDITIONAL PLAN AMENDMENT r5 (owner-requested; answers Step-0 unblock option 1 and r6 §9.1 Q1;
  folds hostile reviews PlanRevA + PlanRevB (r2, 22 findings — see §B.1), PlanRevAr2 + PlanRevBr2
  (r3, 25 findings — see §B.2), and the r5 review closure matrix (§B.3)).
  D12a Option A is OWNER-AUTHORIZED with conditions (§2.5/D12a, §5.4–§5.5); Option B stays deferred.
  Stateful INPUT parity remains unauthorized/deferred: every stateful INPUT miss is E37 DROP until proven Option B.
- Branch: `research/9506-pmech-design` (worktree `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign`), master base `1a6952b61`.
- Date: 2026-09-20. r1: `482bc71c8` (comment `5747342362`); r2: `95a26a17f`; r3: `15ed7d529`; r4: `ddfaec71f`; r5: this follow-up commit on top.
- Sources: r6 plan `/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md`
  (`research/9506-reground @ b4f1d3035`, 2111 lines) + companion
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-delta.md` (126 lines);
  r5 plan `/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md`
  (825 lines); Step-0 gap report `/tmp/pmech-gaps-full.json` (G1–G6); master code at `1a6952b61`.
- Scope: the zone-evaluation mechanism for S5-diverted IPsec-inner traffic ONLY (G1–G5 + G6 accounting).
  Non-goals: implementation, tests, live validation runs, observer exactness (O-*), verdict flips (V-FLIP),
  doc-sync flips (D-SYNC). The evaluator's shadow behavior and side-effect-free transport contract are
  specified in §2.3/§2.6; the shadow-to-enforcing flip PROTOCOL (granularity, authorization, in-flight
  rule, criteria, rollback) is specified in §5.7, but per-tunnel rollout AUTHORIZATION remains owner-level.
- Path convention: every file path in this document is ABSOLUTE and worktree-rooted at
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/`. Relative paths are banned by design brief.

## §0 Decision index

| Gap | Decision (one line) | Section |
|---|---|---|
| G2 tunnel→zone | OWNERSHIP-AWARE if_id join (`config.BindInterfaceOwnsRef` after same-if_id; `StableZoneID` + quarantine); Rust if_id from NEW snapshot tunnel rows (scoped protocol bump); UNZONED/AMBIGUOUS → DROP-and-count | §1.1–§1.3 |
| G2 S12.5 #5 re-sign | **Y** — built mechanism conforms to every normative clause (citations re-grounded; line numbers drifted) | §1.4 |
| G2 S12.5 #6 re-sign | **Y on the choice, identity supplied herein** (`D_usp1` = kernel main table, non-VRF) + 4 kill-conditioned must-proves M1–M4 | §1.5 |
| G2 K2 | NOT triggered. Trigger conditions + re-plan needs stated plainly | §1.6–§1.7 |
| G1 evaluator | 3 layers: Go pre-gate hook + Rust worker-pipeline adjudication via dedicated per-worker queues + `allows()` final guard | §2 |
| G1 doubt | 9-arm definition; doubt → DROP-and-count (enforcing) / divergence-counted ACCEPT or shadow-unavailable (shadow) | §2.6 |
| G3 order | Non-fragmented worker order BY CONSTRUCTION (parse/decap→screen→flow-cache→session→syn-cookie ACK→DNAT/NAT→route→strict-SYN for route-eligible transit→policy→SNAT→install); P-MECH suppresses all challenge TX; validated fragments are an explicit pre-worker E30 exclusion (shadow records divergence + ACCEPT); explicit consult/skip table including NoRoute/punt/HAInactive; Reject≡Deny V1 | §3 |
| G3 INPUT session boundary | Option A AUTHORIZED (stateless ICMP/ICMPv6/flowless + T5 disposition + reply-deliverability proof cell); Option B deferred; stateful misses E37 DROP | §2.5/D12a, §3, §5.4–§5.5 |
| G3 sessions | `SessionKey` + new `Ipsec(if_id)` discriminator (forward + reverse) + NEW cross-discriminator alias index (construction/eviction/multiplicity specified); ambiguity → doubt → DROP | §3.5 |
| G4 deny | Reuse `PolicyDeny`/`UNATTRIBUTED_POLICY_ID` + per-stage events/counters; full taxonomy → DROP-and-count, no silent drops | §4 |
| G5 slice | File list + order + live-proof validation bar + kill conditions; Option A INPUT work is limited to proof-backed stateless shapes; stateful E37 remains | §5 |
| G6/threat | Mechanism targets r6 §1.1/§1.3 residuals; r5 §1 framing cited as STRUCK; narrow delta recorded | §6 |

Conventions: MUST/NEVER etc. per RFC 2119. "DROP-and-count" always means: terminal DROP verdict on the
held NFQUEUE packet (or q0 refusal for bytes never admitted) + exactly one increment of the named counter
+ (Rust side) the named deny event where specified. No silent drops exist in this design.

---

## §1 G2 FIRST: tunnel→zone derivation + S12.5 #5/#6 re-sign (r6 §9.1 Q1 answer)

### §1.1 Tunnel→zone derivation rule

**D1 (derivation function).** The tunnel zone is derived at SNAPSHOT-BUILD time (daemon, same generation
that stages capture) as an OWNERSHIP-AWARE if_id→zone map, and consumed per-frame on the divert path.
(r2: raw-if_id Build reintroduced the #6691 lossy-digest alias — PlanRevA-P1. Ownership is now settled
before any zone claim is recorded.)

1. Inputs (all fail-closed validated before use):
   - Authored: `vpn.BindInterface` per VPN in `cfg.Security.IPsec.VPNs`, and every
     `security-zone <z> interfaces <ref>` member in `cfg.Security.Zones` (compiled `*config.Config`).
   - Derived: `if_id` via `XFRMIfNameAndID` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/xfrmi.go:52`,
     single source of truth; `if_id = stIndex<<16 | (unit+1)` at `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/xfrmi.go:72`; `if_id == 0` ⇔ no device).
   - Ownership: the exported config predicate `config.BindInterfaceOwnsRef(bind, ref)` (wrapper over the
     existing helper at `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/xfrmi.go:273-284`;
     the wrapper is the only daemon-facing API and keeps config as the single source of truth),
     called ONLY after establishing `if_id(bind) == if_id(ref) != 0`. Rule: same base required; a BARE
     ref is owned only by a BARE bind (`!bindHasUnit`); a DOTTED ref is owned by either spelling.
   - Map value: `zoneID = config.StableZoneID(zoneName)`; on tolerant-load snapshots apply
     `QuarantinedZoneNames` — any quarantined/colliding zone claim is marked AMBIGUOUS/unadjudicable
     (never the surviving zone's numeric ID). Strict path: collision rejected at commit (existing gate);
     tolerant-load parity cell in §5.4.
   - Live: the STAGED live-ifindex table (see D1c below) — the ONLY live source the pre-gate reads.
   - Generation: the capture generation (`ipsecCaptureQueueKeys(cfg, generation)` at
     `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go:285-332`,
     r4 D1b semantics — collect metadata for every VPN after per-VPN skip, then fail the generation
     node-wide through `QuarantineAll`)
     plus the authorizing snapshot's `Generation`/`FIBGeneration`
     (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go:561-562`).
   - Rust tunnel rows (NEW, scoped protocol bump): the daemon publishes per-admitted-tunnel
     `{stn, if_id, logical_ifindex}` snapshot rows; Rust D14 derives authoritative if_id by EXACT STN
     match (unknown STN ⇒ doubt ⇒ DROP). There is deliberately NO Rust-side `XFRMIfNameAndID` re-derivation
     (the Rust mirror was deleted rather than re-derived per #6691 — a second parser is a second alias bug).
     Wire: new `MinProtocolIpsecTunnelRows` floor + exact-equality gate; the floor constants are owned by
     `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go:343-389`
     (with `ProtocolVersion` at `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go:327`), not the adjacent explanatory comment at `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go:10-15`.
     Old snapshots without tunnel rows are E33 version-skew/refusal, never `ADMIT_NO_GENERATION`; upgrade
     follows §5.6 lockstep-or-drain (mixed-version DROP window accepted + counted).
2. Lookup path:
   - Build: for each admitted VPN bind `b` with `if_id(b) != 0`, for each zone member ref `r` with
     `if_id(r) == if_id(b)`, record the claim `if_id(b) → zone(r)` ONLY IF `config.BindInterfaceOwnsRef(b, r)`.
     Non-owning same-if_id claims are IGNORED for that bind (they zone nothing). This is the SAME if_id
     join `collectZoneInterfaceRefsAST` uses
     (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/compiler_ipsec_plaintext_warn.go:262-268`),
     PLUS the #6691 ownership settlement that the advisory path never needed (advisories warn; P-MECH selects
     FULL policy, so silent mis-resolution is a mis-zoning risk, not a warning gap).
   - Per-frame: `CaptureOrigin.STN` (which is ALWAYS the authored `vpn.BindInterface` —
     `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go:326` — and is
     re-validated to `if_id != 0` at divert-spec build,
     `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go:37-40`)
     → ownership-checked `if_id` → zone. Cross-check `Origin.OwnedIfindex` against the STAGED live ifindex
     for the frame's generation (D1c; mismatch → doubt → DROP).
3. Fail-closed outcomes (no default zone, no silent inheritance):
   - UNZONED (no OWNING zone claims the bind-device) → DROP-and-count (`zone_gate_unzoned_total` +
     `DenyEventSink` event, §4.1–§4.2).
   - AMBIGUOUS (≥2 zones own claims on one bind-device, or duplicate-if_id across binds, or
     quarantined/colliding zone claim) → DROP-and-count (`zone_gate_ambiguous_total`) + the bounded
     `PMechAlarm` class emitted by the `DenyEventSink` (§4.1–§4.2).
     This is REQUIRED (not inherited first-writer-wins) because: (a) the strict commit gate
     `validateZoneInterfaceMembershipStrict`
     (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/compiler_validate_strict_zones.go:274-314`)
     has a cross-spelling blind spot for st refs — bare `st0` in zone A claims key `st0` while `st0.0`
     in zone B claims key `st0.0` (`zoneIfaceLogicalKeys`,
     `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/compiler_validate_strict_zones.go:213-240`,
     fans bare refs down only over DECLARED `cfg.Interfaces` units, and st units are usually undeclared
     per #4515), so the SAME xfrmi (if_id 1) passes the gate double-claimed; (b) `InterfaceZoneMap`
     (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/host_inbound_effective_view.go:101-154`)
     would then silently first-writer-win it ("evaluating traffic against the wrong zone's policy" —
     the gate's own rationale at `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/compiler_validate_strict_zones.go:302`); (c) tunnel zone selects FULL policy, not just service tokens,
     so silent resolution is a mis-zoning risk. The AMBIGUOUS refusal mirrors #7509/#6727 (same-ifindex
     contest → entry REMOVED from `ifindex_to_zone_id`, "both halves now refuse").
   - `if_id == 0` → refused at staging (per-tunnel skip, D1b) + per-frame doubt → DROP (defense in
     depth; the registry `Register` also refuses empty STN —
     `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/origin.go:52-58`).
   - Stale generation (frame's captured config/fib generation ≠ worker's current) → DROP-and-count
     (fencing, #7167 invariant 5; §2.4).

**D1b (staging partial failure: continue metadata collection after per-VPN skips, then fail the generation node-wide with a bounded alarm).** (PlanRevB-P2.)
`ipsecCaptureQueueKeys` currently returns `nil` + error on the FIRST invalid VPN
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go:300-310`),
failing staging for ALL tunnels. S9.1 changes this to: per-VPN invalid (bad bind-interface,
`LinkByName` failure, missing ifindex) ⇒ record a skip with one bounded `DenyEventSink` event and
`PMechAlarm{class=STAGING_SKIP}` plus `staging_skipped_tunnel_total{reason}`, then CONTINUE building
the metadata for the other tunnels. The closed reason enum is
`IFID_UNDERIVABLE→E3|LINK_LOOKUP→E3|QUEUE_OPEN→E27|OWNER_CONTESTED→E2|DOMAIN_OVERLAP→E21`.
`OWNER_CONTESTED` is only duplicate ownership; M3 overlap uses the distinct `DOMAIN_OVERLAP` value.
Tunnel names are event context only, never metric labels. Duplicate if_id across admitted binds ⇒ ALL
claimants marked AMBIGUOUS + `PMechAlarm{class=OWNER_CONTESTED}`.

Multiple skips are aggregated without iteration-order attribution: the generation carries
`QuarantineReasonMask` (one bit per closed reason) and `QuarantinePrimaryReason`, selected by the
fixed precedence `DOMAIN_OVERLAP > OWNER_CONTESTED > QUEUE_OPEN > LINK_LOOKUP > IFID_UNDERIVABLE`.
Each skipped reason still increments its own staging counter; quarantine DROP events/counters use the
single deterministic primary reason and include the full mask in the bounded alarm. `QuarantineAll`
is therefore one terminal category with a stable E3/E27/E2/E21 owner, never a new taxonomy row.

Because a bad/underivable bind or failed `LinkByName` has no proven per-tunnel kernel match key, ANY
skip (including an empty admitted set) sets
`IpsecDivertSpec{QuarantineAll: true, QuarantineGeneration: g, QuarantineReasonMask: mask,
QuarantinePrimaryReason: primary, CandidateIfindices: stagedCandidates}`.
`ipsecCaptureDivertSpec` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go:19-26`)
MUST pass that explicit quarantine to the nft installer instead of accepting an empty divert spec.
The installer (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nftables/ipsec_divert.go:22-38,123-141`)
uses a separate, higher-priority `xpf_ipsec_quarantine_guard` table for the transition, rather than
trying to ACK a replacement before deleting rules from the same table. Phase 1 installs the guard in
one transaction: a base-chain DROP/counter quarantine plus per-skipped-ifindex DROP/counter rules
and, when zero tunnels are admitted, deny rules for every staged candidate ifindex. If no ifindex is
derivable, the base-chain DROP remains the deny rule. The installer waits for guard netlink ACK and
readback (`QuarantineInstallAck`) before touching `xpf_ipsec_divert`.
`QuarantineInstallAck` is valid only after both inet and bridge families are installed/read back (or a
separately proven equivalent bridge fence is active). The existing inet-only degraded branch in
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nftables/ipsec_divert.go:40-68` MUST NOT
acknowledge quarantine; unavailable bridge nf_tables causes fail/PLAN-KILL for this design rather
than an inet-only guard that lets bridge traffic pass.
The guard does not fence frames already held by the old NFQUEUE actor. Immediately after guard ACK,
the topology/wiring owner closes the old permit/queue epoch, cancels and drains every old in-flight
descriptor/reservation to DROP or structured uncertainty, and waits for the old-generation drain
witness before declaring deny-only or replacing the divert. Any late completion is rejected by the
generation CAS; no old actor may NF_ACCEPT or q0-write under the guard.
Phase 2 invokes the existing atomic replacement (`ipsec_divert.go:40-53`) under the guard.
Before that `Flush`, the installer inspects the old generation's spec metadata. If it is a
`QuarantineAll` spec (including quarantine→quarantine rotation), the guard remains active while the
old quarantine hooks are atomically detached/quiesced, ACKed, final-read, journal-fsynced, and only
then GC'd; failure leaves the guard and aborts replacement. A normal old spec has no quarantine
counter set. Thus no `Flush` can delete an old live quarantine counter without the 3A/3B
quiesce/read/fsync protocol.
The current table's old spec is removed by that same `Flush` commit; there is deliberately no claim of a
pre-removal ACK. If the pre-replacement quiesce or replacement fails, the old divert is treated as
modified/non-live and is NEVER reused as an authority: the temporary guard is the sole deny authority,
and the installer must retry the replacement or reconstruct the old `QuarantineAll` spec under that
guard before any traffic is exposed. There is no “prior generation intact” permit fallback.
**Phase 3A — quarantine activation.** Wait for the `QuarantineAll` replacement readback,
generation/status readiness, and deny fence ACK. The replacement quarantine rules now provide the
steady-state node-wide DROP. Atomically detach/quiesce the temporary higher-priority guard hooks,
preserve their named counters, wait for the two-family detach ACK/readback, and perform the final
guard-counter read/rollup described below. Then remove only that temporary guard; leave the
`QuarantineAll` replacement active. A guard-removal failure retains the guard and raises
`PMechAlarm{class=NODE_WIDE_QUARANTINE}`.
**Phase 3B — quarantine recovery.** When every skip resolves, reinstall the temporary guard and
obtain its two-family `QuarantineInstallAck` (it was removed by 3A). While it is active, atomically
detach/quiesce the existing `QuarantineAll` replacement hooks while preserving their named counters,
wait for detach ACK/readback, and final-read/roll up those replacement counters. Only then
`Flush`/install and ACK the non-quarantine `xpf_ipsec_divert` spec, verify the deny/permit fence, and
quiesce/final-read/remove the temporary guard. If any guard-removal or replacement ACK fails, retain
the guard and stay deny-only; never expose the new divert rules without the guard transition completing.
This is an explicit node-wide outage for those hooks (the current chain sees all traffic, not only XFRM
inner traffic), authorized as the fail-closed failure mode; it is NOT described as a tunnel-only
quarantine.
The renderer exports `ipsec_capture_generation_quarantine_drops_total{reason}` plus
`PMechAlarm{class=NODE_WIDE_QUARANTINE,reason_mask=mask}` through a monotonic counter lifecycle.
The same family/hook counter and quiesce protocol applies to the temporary guard in 3A/3B and to
the `QuarantineAll` replacement counters being retired in recovery 3B; neither path may use a
pre-`Flush` read as its final value.
The inet and bridge guards are separate nft tables, so each has a named counter per
`(family, counting_hook)`:
`xpf_ipsec_quarantine_hits_<family>_<hook>_g<generation>`. The repository pins
`github.com/google/nftables v0.3.0` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/go.mod:8`);
because its `CounterObj` has no userdata field, recovery metadata MUST NOT be attached to a counter.
Each family table also creates a retained, unhooked metadata chain/rule named
`xpf_ipsec_quarantine_meta_g<generation>` whose bounded `Rule.UserData` encodes
`{runID, generation, primary_reason, reason_mask, install_sequence, label_schema}`; a durable journal
is the restart fallback. The metadata chain is not a packet path, remains through hook detach and
counter read, and is garbage-collected only after rollup. If one packet can traverse more than one
guarded hook, the installer designates exactly one first counting owner and later guard rules DROP
without increment; if that ownership/disjointness cannot be proven, admission is PLAN-KILL rather than
summing duplicate hits. The witness enumerates the complete inet/bridge family set and sums only the
designated counting-owner counters. The installer reads and accumulates every family/hook guard counter
before removal for progress, but that snapshot is not final: phase 3 atomically detaches/deletes all
family guard hook chains while preserving every named counter object, waits for the detach ACK/readback,
then reads the now-quiescent counters and rolls each final delta into `{runID, generation,
primary_reason, reason_mask}` before counter-object GC. Thus packets in the read→detach interval are
included. A guard instance has an idempotent install/sequence watermark; removal failure/retry
re-reads only post-watermark deltas, and never double-counts.
Counter-object GC is crash-consistent: after quiesce/ACK/final-read, the
`QuarantineCounterJournal` owned by `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go`
writes and `fsync`s `{runID, generation, family/hook object identities, baseline, final_value,
rolled_up_total, primary_reason, reason_mask, install_sequence, label_schema}` before any named counter
or metadata chain is GC'd. `primary_reason` and `reason_mask` are durable identity, not recoverable
only from transient nft metadata. If the process dies before journal fsync, objects remain and recovery
rereads them; after fsync, recovery treats the record idempotently and does not add `final_value` twice,
whether GC happened or not. A crash after both counter and metadata GC is covered by the journal-only
recovery path: it exports the preserved original `runID` series and the same
`{source,generation,primary_reason,reason_mask,counter_sequence}` dedup identity.
After replacement readiness, the daemon/installer-level `QuarantineCounterWitness` (owned by
`ipsec_capture_wiring_9506.go`/the nft installer and retained even when zero tunnels are admitted
and no capture actor exists) polls the complete live generation family/hook counter set (zero when
the guard is absent, nonzero while a retained guard or replacement quarantine counter is live) and
exports `guard_accumulated + live` in the persistent witness. The collector merges this witness (the
renderer does not increment Go fields per packet) into the quarantine metric; no actor or permit is
required. No valid or skipped tunnel is permitted while that generation is quarantined, and activation
remains deny-only until every skip is resolved and a non-quarantine spec is atomically installed.
This deliberately chooses availability loss rather than guessing a missing kernel match key, prevents
current ACCEPT policy from falling through when no queue rule exists, and makes the generation-wide
staging error an explicit, operator-visible deny-only outage, never an error path or old-spec reuse.

**D1c (live-ifindex source: staged table + generation fence; no per-packet netlink, no stale cache).**
(PlanRevB-P1.) The per-frame name-reuse cross-check reads ONLY the staged live-ifindex table
`{ifname → ifindex}` resolved ONCE per tunnel at staging via the existing `netlink.LinkByName`
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go:304-311`) and frozen IMMUTABLY into the generation. The pre-gate performs a map lookup
(bounded-µs, non-blocking, zero syscalls — D10 contract preserved). Delete/recreate/name-reuse across
generations is closed by the generation fence (D13/D14: frame's captured generation ≠ live ⇒ STALE ⇒ DROP)
+ S4 census revocation (permit CLOSE on topology change); the T12 cell (§5.4) proves mismatch ⇒ DROP.
A staging-cached table refreshed IN PLACE is FORBIDDEN (that is the stale cache the finding rules out):
the table is immutable per generation; rotation publishes a NEW generation and fences the old.

**D1d (VRF-enslavement bypass exposure + fence-ACK proof).** (PlanRevB-P1.) At LOCAL_IN the l3mdev
receive handler substitutes the VRF master for `skb->dev`, so `iifname==stN` divert MISSES while the
master receives the packet. The existing owner can return while the permit is still OPEN and before
the overlay is installed (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_host_fence_reconcile_9506.go:134-135`);
therefore P-MECH MUST NOT claim that every packet is already fenced during attach-to-census detection.
S4 MUST either (A) install a continuously present preemptive master/VRF fence before OPEN that matches
the shared-device ingress independently of the future master name (including every later enslavement),
or (B) leave P-MECH deny-only and record the pre-detection interval as an unresolved permit exposure.
Option A requires the fence rule's future-master matching semantics and a proof that a newly created or
enslaved master cannot receive a packet without the fence. The topology owner polls at
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_topology_owner_9506.go:13-18,62-85,127-151`;
`T_census_max = 1s` is only the attach-to-detection measurement target, not a safety bound. Once
detection occurs, the synchronous fence ACK MUST complete within `T_fence_ack_max = 100ms` before
permit CLOSE completes. If the preemptive fence is absent or unproven, even a measured
attach-to-detection interval ≤1s remains an unresolved exposure and is a PLAN-KILL; do NOT define
`T_bypass_max = T_census + T_fence_ack`. With a proven preemptive fence, every LOCAL_IN/INPUT and
FORWARD packet that would miss NFQUEUE is terminal fence/quarantine DROP, never a permit, counted by
`ipsec_inner_bypass_window_drops_total`; S9.7 measures the ACK and per-hook verdicts. K-P11 kills if
the preemptive fence is absent/unprovable, the post-detection ACK exceeds 100ms or is unmeasurable,
or any packet is permitted during either transition.

**D2 (why ownership-checked if_id, not strings and not raw if_id).** Bind `st0` + zone `st0.0` are the SAME
device when the bind OWNS the ref (`config.BindInterfaceOwnsRef("st0","st0.0") == true`: same base,
dotted ref — `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/xfrmi.go:273-284`,
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/README.md:1301-1303`). String matching
would mis-zone that pairing — the EXACT #5619 bug class
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/compiler_ipsec_plaintext_warn.go:246-253`:
"Matching literally would miss that pairing and report a ZONED tunnel as unzoned").
Conversely a wildcard NIC `st5` zoned `trust` + VPN `bind-interface st5.0` share if_id `0x50001` but the
bind does NOT own the bare ref (`config.BindInterfaceOwnsRef("st5.0","st5") == false` — dotted bind,
bare ref), so the NIC zone MUST NOT zone the VPN — the EXACT #6691 alias
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/xfrmi.go:231-238`: "`st5`, `st05`,
`st+5` all derive if_id 0x50001 while LinuxIfName keeps them DIFFERENT devices"). Raw-if_id Build
would silently inherit the NIC zone for FULL policy selection; ownership-checked Build ignores the
non-owning claim.
Different units (`st0.0` vs `st0.1`) are DIFFERENT devices (if_id 1 vs 2) with SEPARATE capture queues;
zone does NOT inherit across units (a zone on `st0.1` does not zone a bind of `st0.0` — the bind is
UNZONED → DROP with a clear counter; the #5619/#4515 advisory already warns on such configs).

### §1.2 Zone/owner authority (resolves "PROPOSAL/S4-owned", r6 §3.5 item 8)

**D3 (authority split).** r6 §3.5 item 8 deferred tunnel→zone as "PROPOSAL/S4-owned". This amendment splits
permit authority from zone semantics — S4 keeps the former, never owns the latter:

| Artifact | Owner | Grounding |
|---|---|---|
| Zone definitions (`Security.Zones`, member refs) | config/compiler (existing) | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/compiler_security_zones.go`, strict gates `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/compiler_validate_strict_zones.go` |
| if_id→zone map publication (per capture generation) | daemon snapshot/staging path (extends `ipsecCaptureQueueKeys` generation) | wiring `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go:285-332`; snapshot `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go:560-567` |
| Zone CONSUMPTION on the divert path (Go pre-gate + Rust worker entry) | P-MECH (new; this design §2–§3) | — |
| Permit/epoch/rotation authority (OPEN/CLOSING/CLOSED, `tryOpenPermit` requires `ipsecReadySafe`) | S4 (unchanged) | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_reinject_supervisor.go:349-351`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_topology_owner_9506.go:184-243` |
| Shared OPEN predicate at `tryOpenIpsecPermitAfterFenceAck`/`tryOpenPermit` | S4 + P-MECH gate (single writer) | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_host_fence_reconcile_9506.go:109-115`; `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_supervisor_loop_9506.go:35-43` |
| Rust snapshot zone maps (`ifindex_to_zone_id`, `ifindex_unambiguous_zone_id`) | forwarding build (existing) | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/forwarding_build/interfaces.rs`, populated from snapshot interface rows |

The existing host-fence reconciler is an OPEN writer, not merely an observer. Before
`tryOpenPermitAfterFenceAck`/`tryOpenPermit` may CAS OPEN, the shared predicate MUST atomically
recheck `ipsecReadySafe`, the current permit/topology/fence generation, `FailoverRefused` or
`PMechAdmission=DENY_ONLY` (which forbids OPEN), and a generation-bound `PMechFlipAuthorizer`
approval for an enforcing transition. An ordinary SAFE-census reconciliation racing a refusal,
status publication, or incomplete flip loses the CAS and leaves the permit CLOSED; step 7 is the
only successful flip opener.

No dual ownership: S4 gates WHETHER capture is authorized (topology/permit/epochs); it never answers
"which zone". Zone answers come only from the config-owned map above. The r6 §3.5 item 8 citation
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/zones_host_inbound.go` effective tokens) remains the HOST-INBOUND service-token source — P-MECH does
not re-derive host-inbound tokens; INPUT-hook frames consult the existing host-inbound machinery (§3.3).

### §1.3 Alternatives rejected (G2 derivation)

- R1 (inherit `InterfaceZoneMap` string resolution incl. first-writer-wins and unit→base fan): REJECTED.
  Reintroduces the #5619 spelling bug; silently mis-zones cross-spelling double-claims the strict gate
  misses (§1.1.3); drags unit-1 claims onto unit-0 devices. Deterministic ≠ correct for policy selection.
- R2 (derive zone from outer peer / underlay physical interface): REJECTED. Violates r5 H2
  tunnel-identity ("never outer phys zone", `/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md:405`) and #7167 invariant 2
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
| `enqueue_adjudicated` structural provenance; 9506 submits tagged `PacketQueue::Adjudicated` | CONFORMS | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:1056-1061` (`enqueue_adjudicated`), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:1254-1260` (9506 `submit_adjudicated_frame` sends `PacketQueue::Adjudicated` on `tx_delegated`) |
| TC mark `0x58465001` IFF `queue_mapping == 1`; others cleared | CONFORMS | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:35-41` (`ADJUDICATED_QUEUE_MAPPING`, `ADJUDICATED_TRANSIT_MARK`), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:183-187` (clear-then-set), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:282-283` (install) |
| Fence `(xpf-usp1, exact-mark)` conjunction; mark never admitted without its interface | CONFORMS | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nftables/transit_barrier.go:22-43` (`ForwardFenceMark`, `AdjudicatedTransitMark`), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nftables/transit_barrier.go:227-254` (`emitTransitFencePinhole`: `iifname` + `mark` conjunction; empty-ifname/zero-mask refused) |
| Validated `{family,hook,owner,stN,owned_ifindex}` + preserved `nfgen_family`/`hook`/`ifindex` | CONFORMS | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/origin.go:26-35` (`CaptureOrigin`), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/origin.go:72-86` registry, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/nfqueue.go:335-358` (provenance fields observational until validated) |
| inet accepts `{AF_INET,AF_INET6}`; bridge only `AF_BRIDGE` | CONFORMS | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/origin.go:82-86`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/origin.go:120+` (`normalizeCaptureFamily`); `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/nfqueue.go:181-186` (`OpenFamily` bridge bind) |
| Metadata/ifindex/name-reuse mismatch → DROP-and-count, never q0 | CONFORMS | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:312-334` (`Enqueue`: `ValidateProvenance` → `ProvenanceMismatches++` + terminal DROP) |
| Bridge rows never enter q0; inet INPUT has no q0 writer (it terminalizes the held original through the supervisor committer) | DESIGN CHANGE (P-MECH) | Current Go gate rejects both classes at `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:542-548`; S9.1 narrows rejection to bridge/unsupported hooks, admits inet `{forward,input}`; Rust keeps bridge refusal, while §2.1/§2.5 add the conditional INPUT terminal path |
| INPUT permit terminality is an authoritative supervisor `InputPermitCommitter` ACCEPT, never q0 | DESIGN ADDITION (P-MECH; conditional on D12a) | §2.1/§2.5: exact origin + epoch identity + supervisor live-permit/queue/snapshot check; invalid/late completion is DROP; no broad stateful claim until D12a |
| Existing `CompletionAccepted`/`CompletionWouldReinject` not terminal; `ReinjectLease` held through TUN write + epoch-tagged completion ACK | CONFORMS for FORWARD | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:32-44` (`ReinjectLease`), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:623-634` (pending through ACK); `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:221-232` (`ReinjectCompletion`); `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:1434-1437` (lease recheck immediately before write) |
| Revocation cancels queued leases; stale → one DROP; `T_ack≤5ms`; timeout uncertain/no-retry | CONFORMS | `Cancel`/`CancelReinject` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:928`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/reinject_socket.go:184-205`, cancel paths in `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs`); `AckDeadline` default `5ms` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:259-260`); `resolveUncertain` + no-retry terminal rule (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:690-697`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:751+`) |
| Only successful write commits; ambiguous → DROP-and-count / possibly-emitted-never-retried | CONFORMS | `decide_resolve` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:418-432`: Written/Refused/Uncertain + Fenced/Denied/Accepted/WouldReinject); completion decode incl. Fenced/Denied/Accepted/WouldReinject (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:880-885`) |
| MTU-exceeded (live TUN MTU), queue-full, rate-limited → DROP-and-count | CONFORMS | `EnqueueOutcome::{Accepted,RateLimited,QueueFull,MtuExceeded}` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:103-111`); 9506 submit path enforces all three with counters (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:1195-1249`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:1262-1300`) |
| Single-writer q0 + coupling/limiter proof-or-split as S4 must-proves | MUST-PROVE (carried) | Single-writer stated (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:35`: "Queue zero is opened by the sole adjudicated xpf-usp1 writer"); adjudicated+delegated STILL share `tx_delegated` + one `RateLimiter` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:660-661`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:1056-1081`) with per-class admitted/refused counters (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:448-451`) — the §3.5-item-2 proof-or-split cell (G1/T8) is test evidence, not code. Item 5 requires these AS MUST-PROVES ("are S4 must-proves under this... |

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
| ONE shared adjudicated outlet (single `xpf-usp1` q0, all routed-inet tunnels via bounded channel) | CONFORMS | Single TUN, q0 discipline (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:35-38`), bounded `tx_delegated` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:749`), per-tunnel NFQUEUE capture + queue fairness (S3/S4/S5 as landed) |
| MARK-BASED ISOLATION (TC-cleared default + exact fence conjunction) INSTEAD OF per-VRF/RG TUNs | CONFORMS | §1.4 fence/TC rows; `TunSink` measurement-only, explicitly NOT a re-entry path (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/tunsink.go:11-15`); no 9506 TUN creation (no `TUNSETIFF` outside sink + slowpath outlets) |
| Limits q0 to one configured routed-inet domain `D_usp1` | DESIGN-CONDITIONAL → M3 | Existing outlet is single-domain architecturally, but current code has no per-packet VRF/RG/FIB check (the `VRF` field on `IpsecCaptureQueue`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go:34`, feeds ONLY `FragmentKey`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go:233`). D5c M3 adds an expected-domain stamp plus route-resolution and commit revalidation; missing/other domain is E22. |
| Concrete main-table identity written into sign-off before Y | SATISFIED HERE (D5a); was NEVER written before (no `D_usp1` symbol, no record in 9 issue comments or `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/docs/log` — negative grep + remainder map) | This §1.5 is the record. Owner rejection of D5a = N → §1.6 |
| Owner rejects non-main; answers l3mdev question | ANSWERED HERE (D5a) | Same vehicle |
| No admitted xfrmi VRF-enslaved (incl. to `D_usp1` itself); `xpf-usp1` unenslaved | CONFORMS | Census → Unsafe/Unknown → never OPEN (§1.4 row); "incl. to `D_usp1` itself" vacuous-and-true (main is not a master; any enslavement refused regardless of master type, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_topology_owner_9506.go:229-236`) |
| If `D_usp1` were real-VRF/non-main → N for V1 | NOT TRIGGERED (D5a is main/non-VRF) | — |
| Packet bytes carry no VRF/FIB identity | CONFORMS | `SubmitFrame{lease,flow_tag,flags,origin,bytes}` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:141-147`) + `CaptureOrigin{family,hook,owner,stn,owned_ifindex}` — no FIB/table/VRF field on the wire or the struct |
| Every other VRF/RG/FIB + VRF-enslaved capture → DROP-and-count | DESIGN-CONDITIONAL → M3 | Coarse: VRF-enslaved xfrmi ⇒ permit never opens (stronger than per-packet drop — all capture refused). Fine: the P-MECH descriptor carries the expected `D_usp1` route domain and FIB generation; worker route/disposition and commit revalidation MUST return the exact main domain, else E22 DROP. |
| Owned-egress via fence conjunction + MAIN-TABLE EGRESS ORACLE | Fence ✓ / ORACLE ✗ → M2 | Fence admits only marked q0 frames (§1.4); NO egress oracle exists (no post-write domain confirmation; `delivered` witness counts fence matches, not egress table) |
| Shared-device hook/conntrack inventory replaces per-VRF inventory (§3.5 item 4) | GAP → M4 | S4's conntrack work is host-input-fence revocation (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/docs/log/9506-s4.md`), NOT the q0 shared-device inventory; RPF only a bringup warning (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs:2044-2081`); zero hook/RPF/martian/`accept_local` inventory hits in 9506 S4/S5 Go path |
| `W×I≤128` retired | CONFORMS | No per-(worker,instance) TUNs; live bounds are channel depth + rate limits + fairness + 32-tunnel admission (r6 §3.5 item 7) |
| Multi-domain / VRF-singleton / bridge-permit revives option C | CONFORMS (no such claim in tree; bridge-permit refused at two layers, §1.4) | — |
| RPDB steers nothing off main (implied by "ONE main-table domain": PBR/rib-group/next-table rules sit BEFORE main — `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/routing/rules.go:88-90`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/routing/rules.go:64-68`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/routing/pbr_applied_7422.go:22-24` — and CAN match re-injected inner packets; NO iif-`xpf-usp1` exclusion exists in any rule manager — negative grep) | GAP → M1 | The "no rule steers q0 ingress elsewhere" premise (r6 §3.1) is UNPROVEN and likely FALSE under PBR/FBF configs |

**D5c (must-proves M1–M4 — kill-conditioned, owned by G5 §5):**

- M1 (RPDB non-steering proof): prove (live, loss cluster) that with the acceptance config's RPDB
  (PBR/FBF, rib-group, next-table, probe-pin bands), re-injected inner packets resolve via main and no
  earlier rule diverts them — OR ship an iif-`xpf-usp1`-scoped exclusion / RPDB-audit gate that fails
  closed (tunnel DOWN + counted) when a steering rule appears. Kill: steering observed and ungated →
  V1 scope refuses PBR/FBF coexistence (config gate) or K2 re-plan (§1.7).
- M2 (main-table egress oracle): build the oracle item 6 names — post-commit confirmation that q0-egress
  resolved in main (wire-observed egress plus RPDB snapshot check at T2, or equivalent). Kill:
  un-oracleable egress → no V1 claim of single-domain re-entry.
- M3 (overlap/domain admission + commit revalidation — reconciled with D21 and SNAT): the authoritative
  prefix inventory is built at S9.1 staging and published in the immutable per-tunnel snapshot; it is
  NOT read from the Rust forwarding snapshot, which has no compiled VPN traffic-selector inventory.
  The inventory contains `{bind, if_id, local_ts, explicit_remote_ts, effective_prefixes,
  ingress_prefixes, generation,
  fib_generation, source_kind, selector_provenance}`. `explicit_remote_ts` is derived from the same
  effective-selector function the product renders (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/ipsec/policy.go:544-626`):
  named `TrafficSelectors` are expanded exactly as rendered, and when that map is empty a valid
  selector-shaped VPN `RemoteID`/`LocalID` fallback is included with `selector_provenance=legacy-id`
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/compiler_ipsec_identity_ts_8003_test.go:8-10`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/types_security.go:1987-1994`).
  An explicitly authored `0/0` from either source is retained as a ceiling; the function's implicit
  route-based default `0/0` (when no valid selector/ID exists) is marked `implicit` and is NOT an
  explicit selector entry. Local selectors remain identity/policy inputs, not an egress-prefix
  substitute.
- `R_main` is the COMPLETE dump of every installed forwarding route in exact main table 254,
  regardless of route protocol (including FRR BGP/OSPF and other dynamic protocols exposed by netlink);
  filter by forwarding disposition and nexthop ownership, not by `RouteEntry.Protocol`. Non-forwarding
  routes (throw/unreachable/blackhole) and any protocol/disposition the dump cannot classify are
  refusal inputs. `RouteEntry.Interface` is only the first leg; `NextHops` contains every ECMP leg
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/routing/routes.go:26-49,265-268`).
  Expand every route prefix over every nexthop: include that prefix in each tunnel whose authored
  xfrmi owns a resolved nexthop (and include the singular interface when no multipath list exists).
  A route spanning multiple xfrmis is therefore compared against every named tunnel, not assigned by
  first-leg order. Any unresolved/partially resolved nexthop ownership, missing leg, or incomplete
  multipath dump invalidates the complete route inventory and keeps the tunnel(s) DOWN/refused.
  Route/fib generation and ownership must join to the bind; no partial leg is silently omitted.
  The effective set is **intersection, never union**: `effective_prefixes = R_main ∩ explicit_remote_ts`
  (each route prefix is clipped to the matching explicit remote selector). A `0/0` selector is only a
  ceiling for route-derived prefixes; it never supplies a prefix when `R_main` is empty.
  `ingress_prefixes` is not an independent or widened selector: it is the direction-normalized frozen
  copy of this tunnel's non-empty `effective_prefixes` after route/nexthop ownership is resolved.
  It therefore contains concrete route-derived prefixes only; an explicit `0/0` ceiling never becomes
  an ingress member by itself, including when another tunnel has disjoint route-derived prefixes.
- Implicit route-based `ANY/ANY`, missing selectors, an empty route-derived set (including explicit
  `0/0` with no matching route), unresolved xfrmi `oif`, route dump error/partiality, stale
  route/fib/bind generation, or an unjoinable ownership record keeps the tunnel DOWN/refused with
  `DOMAIN_OVERLAP`/E21 only when a real set overlaps, otherwise the relevant E3/E19/E22 counter.
  No partial dump is treated as a complete disjoint set, and no selector-only prefix is admitted.
  At admission, after ownership-aware identity and exact `D_usp1` scope are known, compare every
  tunnel's non-empty `effective_prefixes` against every other candidate; missing/stale inventory is
  never treated as disjoint.
- Without an explicitly proven per-install SNAT carve-out, overlapping prefixes are not admitted.
  Every overlapping claimant is marked DOWN/AMBIGUOUS and packets DROP-and-count (`E21`); no
  first-writer or policy-order tie-break exists.
- With SNAT, overlap is still refused unless the install proves a unique external tuple for every
  forward/reverse entry, a discriminator-aware reverse alias lookup (§3.5), and a commit-time
  revalidation against the same snapshot. SNAT is a narrow identity carve-out, not a way to make
  ambiguous no-NAT traffic safe. V1's main-table scope admits the carve-out only after that proof.
- D21 resolves equal 5-tuples *after* an allowed SNAT install by tunnel discriminator; it does not
  authorize policy-prefix overlap. A post-SNAT reply with more than one candidate remains `E9` and
  DROP. Precedence is identity/zone/if_id, then M3 admission conflict, then policy; no later policy
  result can cure a failed M3 proof.
  Every descriptor carries the expected `D_usp1` routing-domain/main-table identity, the authorizing
  FIB generation, the immutable inventory generation, the zone/policy hash, and the worker `RuntimeView`
  generation. The worker route result MUST return that exact table/domain for FORWARD, and `LocalDelivery`
  in that same domain for INPUT; a missing, other-table, other-VRF/RG, stale, or view-mismatched result
  is E22/E19 doubt → DROP. The frame's direction-normalized ingress address (the inner source for an
  inbound remote selector, or the corresponding selector-directed address for a rendered policy) MUST
  belong to that tunnel's frozen `ingress_prefixes`/`effective_prefixes` set; a 0/0 ceiling is not a
  membership exemption. A missing set or non-member frame is E21 → DROP-and-count, never a shared-q0
  fallback. Immediately before the FORWARD q0 write or INPUT `CompletionInputReady`, revalidate
  route-domain, inventory generation, tunnel membership, ingress-prefix membership, zone/policy hash,
  and view generation against the same immutable snapshot.
  This is the per-frame domain guard; packet bytes need not and MUST NOT pretend to carry VRF/FIB identity.
- M4 (shared-device inventory): inventory every netfilter hook, conntrack/NAT zone, RPF/martian posture,
  `accept_local` and forwarding sysctls for the shared `xpf-usp1` device (r6 §3.5 item 4 retarget);
  unproven hook/zone ⇒ DROP-and-count. Kill: un-inventoried hook/zone on the q0 path.

Kill: any silently admitted overlap, ANY/ANY treated as a disjoint exception, missing/stale/partial
prefix source, route-domain mismatch, or commit revalidation mismatch forces the affected tunnel(s)
DOWN and removes the V1 permitted-flow claim; if the SNAT carve-out cannot be proved, V1 refuses
overlap+SNAT together (VRF separation or PLAN-KILL). Failure to implement the route-domain, inventory,
zone/policy-hash, or view-generation check, or commit-time revalidation accepting another domain, is
E22 plus M3 kill, not a permit.

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

Separate P-MECH gate (not K2): this r3 records owner authorization for D12a Option A's explicit
stateless-only scope. S9.5 may implement or claim INPUT permits only after the two proof cells named
in D12a pass (D12a-C1 worker skip-install/reply deliverability and D12a-C2 T5 host-bound disposition);
every stateful INPUT miss remains E37 DROP until a separately proven Option B. If the owner rescinds
Option A, or either proof fails without a narrower authorized stateless subset, it is a P-MECH PLAN-KILL.
There is no silent fallback to "accept without session".

On K2 trigger: the r6 deliverable (S4-authorization + this P-MECH amendment built on it) is PLAN-KILLED;
§1.7 lists exactly what a re-plan needs. No silent fallback to r5 TUN/VRF, no TAP/L2 revival, no
"capture-only permit" (r6 §6 + K6). This design proceeds through G1/G4 and the conditional G3/G5
mechanism only as a reviewable owner-decision record; it is not implementation authorization until
the D12a proof cells and the M1–M4/K-P gates pass.

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
6. An explicit D12a owner record choosing Option A (this amendment records that authorization and its
   proof conditions) or Option B (two-resource session prepare/finalize, rollback, and accepted-
   without-session kill boundary). Under Option A, every stateful INPUT miss remains E37 DROP; only
   proven Option B can permit stateful INPUT.

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
   before the FORWARD TUN write or the INPUT terminal completion (`decide_pre_write`,
   `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:395-414`;
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
   family/bridge gate (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:542-548`; S9.1 changes the current predicate so bridge and unsupported hooks
   reject, while inet `{forward,input}` continue) and BEFORE `p.lease(frame)` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:549`). Rationale: origin is
   registry-validated by then (`Enqueue`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:312-334`); refusing before lease minting avoids minting authority
   for frames that can never be admitted, keeps `Adjudicated` witness semantics ("lease minted" = passed
   all Go gates), and preserves per-flow head blocking (refused head → `resolveRefusal(reason)`, like lease
   failure `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:550-553`). The typed `ZoneReason` is recorded at this boundary.
- SHADOW invocation (required, not implied): in `consumeFrames`
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:383-428`), after
  provenance/classification partitioning and before the current shadow `finishFrame(frame, VerdictAccept)`
  at `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:418-420`, call `evaluateShadowFrame`. That helper calls the same typed Go pre-gate and enqueues
  a `ShadowFrame` on the bounded side-effect-free Rust shadow transport (§2.3); it MUST NOT call the
  production permit/verdict path. Rust returns only a read-only decision/ledger diff. A post-read zone
  or Rust refusal is `ShadowDivergences` plus ACCEPT; nil/stale evaluator, shadow transport full,
  dead worker, or unavailable snapshot is `shadow_unavailable` plus ACCEPT, never an implicit enforcing
  DROP. This explicit call site retains r5 §4.6 without allowing shadow to mutate production state.
- SECONDARY (attribution only): `receiveQueue`
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go:211-246`).
  Plumb the queue's tunnel association (`captureQueue` already carries `Tunnel`/`VRF`/`Generation`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go:31-36`) into `CaptureFrame` as ADVISORY attribution when building the frame
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go:231`), so drops that
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
Fail-closed nil contract (mirrors `ErrNoLeaseMinter`/`ErrNoSubmitter`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:166-167`):

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
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:640-655`).
### §2.3 Rust transport: dedicated per-worker ingress queues (NOT WorkerCommand packets)

**D11.** IPsec-inner frames reach workers over NEW dedicated per-worker bounded MPSC ingress queues
carrying POOL-SLOT DESCRIPTORS. Rationale (r5 §4.3 contract: "Double-buffered in-flight ≥ 2 batches;
bounded worker→capture verdict queue; capture thread never blocks; Heap: pooled slabs, no hot-path
allocation; batch rows carry (slot, len, tunnel key, flow key, queue-epoch, phase epoch …)"):

- Descriptor (Rust-internal, never on a socket): `{slab_id, len, tunnel_if_id, stn_ifindex, flow_tag,
  advisory_zone_id, advisory_if_id, expected_routing_domain=D_usp1, expected_fib_table=main,
  permit_epoch, queue_number, queue_epoch, snapshot_generation,
  config_generation, fib_generation, phase_epoch, worker_set_generation, request_id, flags}`.
  Immutable once enqueued (origin immutability mirrors `CaptureOrigin` registry semantics,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/origin.go:26-35`).
- Pool: Rust-side slab pool (`PooledSlab`, hard cap `IPSEC_INNER_SLAB_CAP`; initial S7 sizing is
  512 descriptors, never an unbounded allocator). Socket recv writes DIRECTLY into an acquired slab.
  The shared Rust logical-ingress helper currently allocates `Vec<u8>` of `14 + len`
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:79-85`);
  P-MECH MUST either route that copy through the acquired slab or charge its bounded allocation and
  reject when the per-worker admission budget is exhausted. It MUST NOT claim “no allocation” while
that `Vec` remains. Go's receive/socket copy is separately priced in S7. FORWARD ownership is
`socket server → worker → q0-writer → pool-release`; release happens exactly once on every terminal
outcome (Written/Refused/Uncertain all release; write-started holds through definitive outcome, as
`ReinjectLease` requires). INPUT is a separate ownership branch: after posting
`CompletionInputReady` or `Deny`, Rust performs an `InputSlabRelease` CAS exactly once and returns
the copied slab to the pool; it does not pass through q0 and is independent of the Go-held NFQUEUE
packet/committer reference.
- Per-worker bounded queue (initial cap `IPSEC_INNER_QUEUE_DEPTH=128`, final value S7/T22-owned; full
  → DROP-and-count + `ipsec_inner_worker_queue_full_total`, socket-server never blocks — r5 "capture
  thread never blocks", `/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md:240-242`). Per-flow in-flight descriptors are bounded at 128; exceeding
  the bound refuses the new frame rather than growing a `Vec`/list.
- Owner routing: `flow_tag` (FNV-1a of `FlowKey`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/reinject_socket.go:524-527`) →
  stable hash mod LIVE worker set. Same flow → same worker → per-worker FIFO preserves per-flow order
  (r5 §4.3; the queue joins `ReinjectCore.flow_order` as the cross-worker sequencer record).
  `worker_set_generation` is CONTROL-published and checked before adjudication; a descriptor for a
  retired set is stale → DROP-and-count, never misrouted.
- Dead-worker handling is explicit: a supervisor/reaper scans worker liveness at a bounded interval
  (initially 1 ms, S7-owned), marks the worker-set generation retired, drains its queue, and
  terminalizes every orphan descriptor exactly once before releasing slabs. No orphan may
  remain held until an unbounded reconnect; no new descriptor routes to a retired worker.
- Every provisional handle is registered in a shared `ProvisionalJournal` before any worker mutation:
  `{token, owner_worker, owner_generation, phase=Prepared|WriteStarted|Committed|RolledBack,
  session_refs, nat_undo, request_ids, generation}`. The journal is bounded by the slab/descriptor cap
  and is not a best-effort log. A worker crash or queue retirement leaves a journal record for the
  reaper: `Prepared` is rolled back exactly once; `WriteStarted`/`Committed` is conservatively
  finalized as committed (q0 may have emitted), terminalized as uncertain/drop, and retained under
  the existing generation/expiry wheel for bounded cleanup; it is NEVER blindly rolled back. The
  reaper emits `ipsec_inner_orphan_provisional_total` and a witness reason, and a surviving owner
  may only close the record through the journal CAS. This resolves verdict-issued handles without
  relying on a dead worker or leaking a live NAT/session reservation.
- Bounded poll budget: each worker drains ≤ `IPSEC_INNER_DRAIN_BUDGET` descriptors per poll pass
  (r5 §4.4; same discipline as `WORKER_COMMAND_DRAIN_BUDGET < MAX_PENDING_WORKER_COMMANDS`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/worker_queue.rs:591`).
  IPsec-inner work is a named bounded fraction of the AF_XDP poll budget, priced by T22/S7; neither
  physical nor diverted ingress may starve the other.
- Bounded verdict queue back (worker → `ReinjectCore`): `{request_ids, verdict: Permit{mutation_applied,
  commit_mode: ForwardQ0|InputReady, provisional: Option<ProvisionalStateHandle>} |
  Deny{stage, reason, policy_id}, snapshot_generation, worker_set_generation, event_flags}`.
  `InputReady` is NOT terminal; under authorized Option A every INPUT miss is stateless and
  `provisional` is `None` (no session, BPF flow-cache, HA, or stateful-counter publication).
- `ProvisionalStateHandle` is a typed, opaque Rust-owned record:
  `{owner_worker, owner_generation, token, session_refs, nat_undo}`. The owner worker alone consumes
  it: successful q0 write linearizes `CommitProvisional(handle)` before `CompletionWritten`; refusal
  sends exactly one `RollbackProvisional(handle)`. ACK timeout/uncertain does NOT roll back because
  the write may have succeeded; state stays committed and the outcome is never retried. Existing-hit
  permits with no new state carry `None`; Go transports but cannot finalize the handle.
- Shadow is a separate bounded transport, not a production verdict replay: `ShadowFrame` carries an
  immutable slab reference plus the captured snapshot/zone/generation, records `phase=Shadow`, and
  carries `observed_permit_epoch` as read-only evidence only (it is NOT an authority token), no
  production `ReinjectLease`, request ID, q0 writer, or INPUT committer token.
  The ledger's terminal accounting is separate from slab memory ownership: a
  `ShadowResultTombstone` CAS wins the outcome, but a `ShadowSlabLease` refcount/hazard epoch keeps
  the immutable bytes alive while a worker may still read them. Queue-full before enqueue may release
  immediately; for a completed decision, dead-worker reap, timeout, or stale-generation drain, the
  final `ShadowSlabRelease` CAS occurs only after worker completion/cancellation acknowledgement (or
  the hazard/refcount grace condition). A late result is discarded by the tombstone and cannot cause a
  second accounting event or early pool reuse. S5.4 tests both the result CAS and post-ack release.
- It enters the worker with `EvaluationMode::Shadow`. Shadow execution has no q0 writer, no NFQUEUE
  terminal, no session/NAT allocation, no BPF flow-cache/HA publication, and no production dataplane
  policy-counter mutation; attempted side effects and bounded divergence/unavailable counters are
  redirected to `ShadowLedger`/witness only. An in-flight shadow result can report only divergence or
  `shadow_unavailable`; it can never authorize an enforcing descriptor or be joined to a production
  completion.
- A stage that cannot prove this side-effect-free contract returns `shadow_unavailable` rather than
  running its production mutator. Shadow queue-full/dead-worker uses the same bounded unavailable
  accounting and ACCEPT-preserving semantics in §2.2; it cannot block capture or authorize enforcing.
  Verdict-queue-full is counted (`ipsec_inner_verdict_queue_full_total`) and alarmed, never silent.

**D12a (INPUT session boundary; Option A authorized with conditions).** Existing INPUT session HITS are
consulted and revalidated, but stored NAT metadata that would rewrite/translate is E36 DROP. Broad
stateful INPUT parity (TCP/UDP/SCTP, application/ALG, and any flow that requires a new session) still
requires an atomic relationship between NF_ACCEPT and worker-owned session publication; the
`InputPermitCommitter` alone does NOT provide that relationship.

- **Option A — AUTHORIZED for this design, narrow and conditional:** allow only explicitly stateless
  ICMP/ICMPv6 and flowless L3 shapes whose existing worker path does not require a session. A local
  INPUT MISS performs full screen/host-inbound/policy evaluation, but MUST NOT install or publish a
  session, BPF flow-cache entry, HA record, or stateful policy counter. TCP/UDP/SCTP, application/ALG,
  and every `strict_syn_check_drops_new_flow`-ineligible or session-required miss are DROP + E37.
  This authorization does not claim broad INPUT parity.
- The authorization is contingent on two proof cells before S9.5 permits: (1) `D12a-C1` must show the
  worker path skips session/flow-cache install for the exact stateless ICMP/ICMPv6 shapes and that the
  reply is deliverable through the proven host path; (2) `D12a-C2` must record the host-bound disposition
  for both verdicts. If either fails, narrow the allowed set to the proven shape(s), or authorize no
  INPUT permits; never silently widen to stateful parity.
- **Option B — deferred:** full INPUT parity requires a bounded two-phase session prepare/finalize
  protocol with an accepted-without-session residual explicitly owned and kill-gated. It is not
  wire-specified here and MUST NOT be invented by treating `CompletionInputReady` as a session commit.

Until both proof cells pass, every authorized-Option-A INPUT permit remains blocked; every stateful miss
is E37. If Option A's proof passes, each stateless miss is fully re-adjudicated and the per-flow head
remains blocked until supervisor commit. Option B remains deferred, not an implicit fallback.

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

- `inner_packet` = slab bytes for one admitted non-fragmented datagram; validated fragments are refused before
  socket/worker admission (§3.6). `inner_family`/`inner_eth_proto` come from the Go classification
  (re-validated in Rust — Go classification is advisory, Rust parse is authoritative; mismatch → doubt → DROP).
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
- `RuntimeView`: the P-MECH entry receives the one immutable view binding already loaded by the
  worker poll/tick and MUST make zero new `RuntimeView`/`shared_runtime.load()` calls
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/worker/loop_body/mod.rs:60-159`;
  view/setup publication `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/worker/loop_body/setup.rs:122-130`).
  D14 and every later stage use that same binding; no second snapshot read may interleave. A refresh
  after admission leaves the descriptor on its old view and the final lease/generation/zone/policy-hash
  check drops it (E4/E22/E33 as applicable), never mixing views. The reader-load canary in
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/tests/runtime_view_publish_canary.rs` guards
  this zero-new-load contract.
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
the `allows()` epoch check: (a) exact tunnel-row/protocol-floor presence and equality. A missing tunnel
row, unknown row, or old snapshot is E33 version-skew/refusal (`ADMIT_TUNNEL_ROW_MISSING`), never a
missing-generation success; (b) config/fib generation presence (non-zero and wire-valid — missing is E5
`ADMIT_NO_GENERATION`); (c) slab availability (pool exhausted ⇒ `ADMIT_FULL` — an existing code, no new
variant needed). Fragment metadata never reaches this socket admit: §3.6 rejects it before `FragPool`/
worker admission, so no fragment-group `ADMIT_BAD_LEASE` or batch code is introduced. The only new
socket-known admit codes are `ADMIT_NO_GENERATION = 11` and `ADMIT_TUNNEL_ROW_MISSING = 12` (the
intermediate values are reserved and unknown values refuse). D14's zone/if_id/`RuntimeView` checks
run only after worker admission and report `Deny{stage,reason,...}` through the completion taxonomy;
they MUST NOT be represented as `ADMIT_NO_ZONE`, `ADMIT_ZONE_CONTESTED`, or `ADMIT_STALE_CONFIG`.
Go's `decodeAdmissions` maps any unknown code to refusal and MUST never default it to `ADMIT_OK`.
The old generic input-hook refusal is narrowed, not deleted: `{inet,input}` is admitted to the worker;
`{bridge,input}` (and every non-inet/unsupported hook) remains a structural refusal and never reaches
policy. For `{inet,input}`, the worker MUST NOT call `submit_adjudicated_frame`, set the q0 mark, or emit
`CompletionWritten`. After the final `allows()` check it emits a NEW non-terminal
`CompletionInputReady` carrying request/permit/queue epochs, `snapshot_generation`, zero `BytesWritten`,
and an optional session-ref set ONLY under a future owner-authorized full-session option. Under the
authorized stateless scope, the set is empty. `CompletionInputReady` means "worker prepared; supervisor
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
type TerminalAttemptState uint8
const (
    TerminalAttemptUnknown TerminalAttemptState = iota // zero is conservative: treat as attempted
    TerminalAttemptNo                                  // explicit proof: no sink syscall was attempted
    TerminalAttemptYes                                 // sink syscall may have linearized
)
type InputPermitCommitOutcome struct {
    Result            InputCommitResult
    TerminalAttempted TerminalAttemptState
    Err               error
}
type InputPermitCommitter interface {
    CommitInputAccept(InputPermitCommit) InputPermitCommitOutcome
}
```

The adapter and resolver MUST interpret the structured outcome, not infer terminal state from an error
string. `Accepted,nil` means supervisor NF_ACCEPT already issued and performs no sink call;
`Accepted,error` is E35 uncertainty with no second sink call; `Dropped,nil` means supervisor NF_DROP
already issued and performs no second sink call. `Uncertain,*`, `Dropped,error`, or any invalid/unknown
result with `TerminalAttempted=TerminalAttemptYes` or `TerminalAttemptUnknown` is uncertainty accounting
with no sink call or retry; zero/unknown is deliberately conservative once the committer was entered.
Only `InputCommitInvalid`/unknown returned BEFORE committer entry with explicit
`TerminalAttempted=TerminalAttemptNo` may use the retained `sinkHandle` to issue one DROP. A callback
that does not prove no terminal attempt is never converted into a definitive DROP. The adapter MUST
preserve this typed outcome through the resolver callback. The adapter registers each capture queue as
the matching immutable supervisor gate kind (`ipsecGateInput` for inet/input), builds `ipsecPacketRef`,
and calls `ipsecSupervisor.commitValidatedVerdict` with the live permit record. That existing method
holds `commitLease.RLock` from full permit/gate/queue/snapshot validation through the packet sink syscall
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_reinject_supervisor.go:602-656`);
the adapter MUST NOT use the generic `CapturePipelineConfig.Sink` fallback
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:275-281`) for ACCEPT.
On supervisor refusal the helper itself emits exactly one DROP and returns the structured
`{Result: InputCommitDropped, TerminalAttempted: TerminalAttemptYes, Err: nil}`; this is a definitive
terminal and does not enter uncertain accounting or invoke a second sink call. An error after fd
syscall entry returns `{Result: InputCommitUncertain, TerminalAttempted: TerminalAttemptYes, Err: err}`.
A post-committer `q.mu` acquisition timeout before any fd syscall returns
`{Result: InputCommitUncertain, TerminalAttempted: TerminalAttemptNo, Err: q_mu_timeout}` and E35.
A refusal proven before committer entry returns `{InputCommitInvalid, TerminalAttempted: TerminalAttemptNo, Err: err}`;
only that pre-entry outcome may use the retained handle for one DROP.
`submitGate` only orders against pipeline cancellation; it is not an S4 authority check.
Because this method currently holds `commitLease.RLock` across the sink syscall, S9.1 MUST make every
fd-send path bounded. `Packet.Verdict` sends on a queue-wide fd while holding `q.mu`, and
`VerdictBatch` holds that mutex across `sendmmsg`
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/nfqueue.go:266-283,418-437,459-504`);
`Queue.Close` also needs `q.mu`, so a stalled batch can otherwise block INPUT and close. The contract
must use a bounded/nonblocking `q.mu` acquisition plus `SOCK_NONBLOCK`/`SO_SNDTIMEO`; moving socket
I/O outside the lock is not an accepted shortcut because fd lifetime/close fencing would otherwise
be a second unbounded authority. Bounding only `unix.Send` is insufficient. A proven EAGAIN/timeout
returns `{Result: InputCommitUncertain, TerminalAttempted: TerminalAttemptYes, Err: timeout}` and
records E35.
If bounded `q.mu` acquisition itself times out after committer entry but before any fd syscall, it
returns `{Result: InputCommitUncertain, TerminalAttempted: TerminalAttemptNo, Err: q_mu_timeout}` and
records E35; this is not the pre-committer invalid case, so no retained-handle DROP fallback or retry
is allowed.
For uncertain outcomes only, `TerminalAttempted: TerminalAttemptYes` means the fd send was entered and
may have linearized (EAGAIN/timeout or another post-entry error); the definitive supervisor-refusal
`Dropped,nil,Yes` outcome above is the explicit exception. For either a post-committer lock timeout
or an attempted-send error, the recovery is generation-scoped: fence the queue epoch and stop new
admission, CAS every still-held reservation to uncertain exactly once, then perform a single queue-wide
`Queue.Close`/rebind teardown to let the kernel drop the held packets (never present this collateral
close as a per-packet cancellation). Open a fresh queue epoch only after the old held set is drained
and its uncertain counts/witness are complete; traffic never resumes on the wedged epoch.
The epoch-drain census is exhaustive before rebind: Go `p.pending`, per-flow pending/head queues,
`InputTerminalReservation` states, held packet/sink refs, FORWARD `ReinjectLease`s, socket completion
maps, Rust per-worker ingress descriptors (queued and currently adjudicating), verdict completions,
`ProvisionalJournal` records, and every slab/ShadowSlabLease owned by that queue epoch are enumerated
and terminalized/released under generation CAS. The drain witness must show zero old-epoch owners
and one terminal accounting per item; late worker/completion messages are discarded after the CAS.
The bounded send returns and releases `commitLease.RLock`; supervisor close first fences new permits,
then waits for committer completion/RUnlock under `T_input_commit_max` and MUST NOT call queue-wide
`Close` as a per-packet cancellation. A context deadline alone is not a bound. If the implementation
cannot prove the nonblocking/bounded send, it must redesign queue-close synchronization and account
for queue-wide collateral; otherwise this design is PLAN-KILL, not an unbounded wait.
S5.4 includes a blocking-sink test that proves `EAGAIN`/timeout mapping, no `q.mu` close deadlock,
bounded close/RUnlock, structured uncertainty, and exactly-once accounting.
The Go completion resolver accepts `CompletionInputReady` only for exact `{inet,input}`, zero bytes, and
matching request/permit/queue/snapshot identities. Under `p.mu` it atomically creates a bounded shared
`InputTerminalReservation{RequestID, flowID, heldPacketRef, flowHeadToken, sinkHandle, state=Reserved,
deadline, accountingOwner}` and only then removes the matching `RequestID` from `p.pending` and clears
the corresponding `flow.pending` entry. The reservation retains the held-frame/sink authority and
exactly-once accounting owner until terminal CAS; an absent, duplicate, or already-cancelled identity
is E35 and cannot enter the committer.
The resolver changes `Reserved→Committing` before taking `commitLease.RLock` or entering the supervisor
committer; the packet sink and lease authority are never called while `p.mu` is held. A
`CancelReinject` racing in `Reserved` CASes the reservation to `Cancelled`, uses the retained
`sinkHandle` to own exactly one DROP terminalization, and removes the map entry; the resolver observes
that CAS and does not call the committer. Once `Committing`, cancellation cannot create a second
terminal: the committer's live epoch check returns DROP or uncertain, and the resolver records that one
outcome without retry. A bounded reaper owns any reservation still `Reserved` at its deadline and CASes
it to `Cancelled`/DROP through the retained sink handle. A reservation still `Committing` at its
deadline is CASed to `Uncertain` only: the reaper MUST NOT issue a definitive DROP because NF_ACCEPT
may already have linearized inside the blocking committer; a late callback is discarded by the terminal
CAS, never re-enters `p.pending`, and never retries.
The resolver invokes the committer: `InputCommitAccepted` means the supervisor has already NF_ACCEPTed
the original held bytes, so the resolver performs a sink-skipping terminal pop/accounting operation (no
second `finishFrame` sink call), records exactly one terminal result, and advances the per-flow head.
`InputCommitDropped` records one DROP without a second sink call; `InputCommitUncertain` records
uncertain accounting and never retries. A committer timeout, panic/error after an unknown sink outcome,
duplicate, or late completion is uncertain/E35 and terminalizes the reservation/accounting state exactly
once (not a second sink verdict). A completion
outcome carries an `event_emitted` bit: Rust emits only for frames that reached Rust, while the Go
`DenyEventSink` owns pre-dispatch failures; the resolver emits a transport/completion failure only when
that bit is clear, preventing duplicate events. A `bytesMismatch` check MUST NOT reject this path solely
because `BytesWritten == 0`; the zero-byte exemption is valid only for this exact INPUT identity and
`InputCommitAccepted`.
Existing `CompletionAccepted`/`CompletionWouldReinject` remain advisory/nonterminal for FORWARD and are
NOT aliases for `CompletionInputReady`.

`allows()` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:381-394`) is UNCHANGED (permit/queue epochs + tombstones + open).
It remains the final pre-write guard for FORWARD and the final pre-`CompletionInputReady` guard for INPUT
via `decide_pre_write` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:395-414`). NO policy/zone/session predicate enters `allows()` — D6 separation.
The authorized stateless scope does not claim broad INPUT session parity; the full-session requirement
and kill/scope decision are D12a/G5.

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
   `MinProtocol*` floors; Go/Rust wire-codec mismatch — exact-equality gates,
   `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go:343-389`).
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

**D17.** A NON-FRAGMENTED owned IPsec-inner frame runs the WORKER PIPELINE'S EXISTING stage order BY
CONSTRUCTION (D13 entry feeds the same code GRE/WG-owned frames traverse). Validated fragments are an
explicit D22 pre-worker exclusion: enforcing frames E30-DROP before screen/worker admission, while
shadow frames record a would-drop divergence and remain ACCEPT. G3 therefore specifies (a) the
non-fragmented order as observed (pinned, not re-derived), (b) per-stage CONSULT-vs-SKIP for that class
with reasons, (c) conflict precedence, and (d) session-identity rules that differ from native by
necessity. NOTHING in the non-fragmented worker order is reordered for P-MECH; skips are enumerated
exhaustively in §3.2 (any stage not listed there is CONSULTED).

Pinned order (forward/miss path, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs`) is the actual worker order, including work that
precedes the first security decision: parse/decap and owned-frame construction → `stage_screen_check`
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:446`) as the FIRST security stage → flow-cache lookup
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:628-641`) through the
P-MECH decision-only helper (metadata only; no UMEM recycle, TX, or permit) → session resolve
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:752-753`) →
[HIT: established revalidation §3.4] / [MISS: syn-cookie ACK validation before DNAT
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1720-1738`); any screen challenge or syn-cookie reply
that would call `enqueue_syn_cookie_reply`
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:462-474`) is SUPPRESSED for P-MECH, the original packet
is E7/E37 DROP, and no worker TX is emitted] → static-DNAT/DNAT
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1774-1789`) →
NPTv6/NAT64 as configured → route/disposition (NoRoute is `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5799`)
→ strict-SYN check ONLY for route-eligible `ForwardCandidate`/`MissingNeighbor`
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2522`) →
LocalDelivery: host-inbound (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2625`) → `junos-host`
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2734`) / transit: zone-pair policy
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2962`, post-DNAT tuple
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2021-2064`) → permit-only SNAT alloc
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3207`) → session install
and reverse publication (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3433`,
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3919`) → NAT counters at committed install.
P-MECH SKIPS the DNS fastpath entirely (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3296-3309`);
it MUST NOT call `dns_reply_fastpath_admit` or use a no-NAT shortcut. DNS/UDP INPUT misses use the
normal session path and E37 unless already an exact established hit. HAInactive
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4150`) and punt-seed
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4171`) are guarded
E34 DROP arms: no redirect, punt, or local session seed.

INPUT has a deliberately distinct terminal path after the shared parse/decap, screen, fragment-shape,
and flow-cache stages. The capture rule is an NFNETLINK input chain at priority `-175`
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nftables/ipsec_divert.go:17-20,193-198`), so
the held bytes are post-kernel-prerouting but PRE-product/userspace-NAT. Its remaining order is session
resolve → product NAT decision-only checks (static-DNAT/DNAT/NPTv6/NAT64; any matching rewrite or
cross-family translation is E36 DROP) → route/disposition check (MUST be `LocalDelivery` in exact
`D_usp1`) → host-inbound admission/lo0 → `junos-host` policy → **session boundary D12a**. A permit emits
`CompletionInputReady` only after the terminal epoch guard (§2.5), and then the supervisor adapter
NF_ACCEPTs the same bytes. Under authorized Option A, only stateless ICMP/ICMPv6/flowless shapes may
reach this permit; stateful misses take E37. Option B is deferred for broad stateful INPUT parity.
Deny at ANY stage ⇒ terminal DROP + §4 deny path; later stages skipped (deny-overrides, §3.3).

### §3.2 Consult-vs-skip table (owned IPsec-inner frames; both hooks unless noted)

| Worker stage | FORWARD | INPUT | Reason |
|---|---|---|---|
| Parse/decap + owned-frame construction | CONSULT | CONSULT | Parse is before the first security stage; malformed inner parse/ECN is DROP-and-count, never a default-zone permit. The shared `build_logical_ingress_packet` remains authoritative. |
| `stage_screen_check` (from-zone screen) | CONSULT | CONSULT | FIRST security stage, every packet hit or miss (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:446`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4335-4336`); skipping creates an unscreened ingress class. |
| Fragment metadata/shape gate | ENFORCING: E30 DROP before `FragPool`; SHADOW: would-drop/divergence + ACCEPT before `FragPool` | Same | Reuse `ClassifyCapturePayload`/`FragmentKey`/`FragmentPiece` validation; V1 never reassembles or permits fragments, so no cache/session/NAT/policy stage runs for this class (§3.6). |
| Flow-cache lookup/hit | CONSULT only with exact `Ipsec(if_id)`, generation, policy/NAT hash, and screen revalidation; P-MECH helper is decision-only | Existing exact hit may be CONSULTED; cache miss/new install is SKIP → normal session path | A native/old cache row lacking tunnel discriminator or generation is invalidated and treated as miss; the helper never recycles UMEM or emits TX; Option A never seeds a new INPUT cache row. |
| Session lookup (shared + worker-local scopes) | CONSULT | CONSULT | Single session universe (§3.5); no second table. |
| Syn-cookie ACK validation (pre-DNAT) | CONSULT on miss; challenge/reply TX suppressed and failed validation is E37 | CONSULT; stateful miss outside Option A ⇒ E37 | ACK validation is `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1720-1738`; P-MECH never calls `enqueue_syn_cookie_reply` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:462-474`) and never emits a worker challenge. |
| DNS fastpath | SKIP for P-MECH; fall through to normal stages | SKIP for P-MECH; fall through to normal stages | `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3296-3309` is not an admission/session bypass; no `dns_reply_fastpath_admit` call, no no-NAT shortcut, and new DNS/UDP INPUT misses are E37. |
| Established-hit revalidation (#8356 policy, #3706 host, #7212 filter, `session_hit_authority` arrival-zone) | CONSULT | CONSULT; stored NAT rewrite/translation ⇒ E36 DROP | Hit authority is by construction; INPUT cannot accept an established translated session unchanged. |
| static-DNAT → DNAT (+ counter split) | CONSULT | CONSULT (decision-only: no-match/identity continues; any product rewrite ⇒ E36 DROP) | Junos pre-routing order for FORWARD; INPUT cannot replace an NF_ACCEPT payload, so a matching product rewrite is fail-closed. |
| Route/disposition resolve (userspace FIB) | CONSULT | CONSULT — after the no-mutation proof, MUST resolve `LocalDelivery` in exact `D_usp1` | FORWARD determines egress + to-zone and MUST return the exact main-table/routing-domain identity; INPUT validates that the held pre-product-NAT tuple remains host-bound in that same domain. Other-domain/other-table result is E19/E22 doubt → DROP. |
| NoRoute / FIB miss (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5799`) | GUARD: E19 DROP; native NoRoute arm unreachable/SKIP | GUARD: E19 DROP; native NoRoute arm unreachable/SKIP | No route is a doubt; neither hook gets an implicit default route or permit. |
| Strict-SYN check (after route; only `ForwardCandidate`/`MissingNeighbor`) | CONSULT; failed new-flow check is E37 and any challenge TX is suppressed | SKIP → E37 for INPUT (not route-eligible transit; session boundary handles INPUT) | The check is `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2522`; it is not run before DNAT/route. |
| HAInactive / redirect (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4150`) | GUARD: E34 DROP; no redirect or local session seed | GUARD: E34 DROP; no redirect or local session seed | P-MECH cannot redirect or consult a second outlet while the attachment is inactive. |
| Punt-seed (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4171`) | GUARD: E34 DROP; no seed | GUARD: E34 DROP; no seed | P-MECH's owner-worker verdict and q0/input terminal are the only outlets; a punt seed would create an unowned second path. |
| Zone-pair policy (`evaluate_policy_result_with_icmp`, post-DNAT tuple, live ICMP type/code) | CONSULT | N/A (host path instead) | THE zone enforcement (from = tunnel zone D14, to = `egress_zone_id` unambiguous map — NEVER `ifindex_to_zone_id` for to-zone, #6722/`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/forwarding/mod.rs:235-250`). |
| Host-inbound admission + lo0 gate | N/A | CONSULT | Mirrors physical LocalDelivery miss (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2625`); kernel `xpf_hostinbound` chain re-judges post-ACCEPT at the input hook — AND-composition (both must permit), documented layering, no conflict. |
| `junos-host` policy (`junos_host_local_policy`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/host_inbound_policy.rs:254`) | N/A | CONSULT | Runs AFTER host-inbound admission ("Junos order", `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1567-1570`); deny/reject ⇒ DROP + policy-deny RT_FLOW (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1570`). |
| SNAT / static-SNAT / NPTv6-outbound alloc (permit branch only) | CONSULT | SKIP | FORWARD: Junos post-policy source translation; applied to q0 bytes pre-write (r6 §3.2 step 1 "PERMIT-with-mutation"). INPUT: NO SNAT on local-delivery path (precedent `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2870-2874`); NF_ACCEPT releases the held bytes unchanged. |
| Session install (forward+reverse, policy-counter stamp, generation stamp) | CONSULT (permit REQUIRES install; install-fail ⇒ DROP) | D12a boundary: Option A SKIP new-session install and publish (stateless only); Option B REQUIRED full-session prepare/finalize, not yet designed | Forward-permit without install would orphan return traffic; FORWARD install is part of permit (precedent: refusal ⇒ rollback + DROP, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3319-3323`). INPUT broad parity is a kill-gated open requirement. |
| NAT rule counters (DNAT+SNAT independent Arcs, once each at committed install) | CONSULT | SKIP for no-match/identity; E36 mutation cases are not committed | FORWARD counters are committed exactly once; INPUT never mutates or double-counts product NAT. |
| BPF session-map publish + flow-cache seed | CONSULT | Option A SKIP; Option B REQUIRED before claiming broad parity | Return traffic (LAN→tunnel via workers/XDP) needs the session visible; P-MECH does not silently publish INPUT state before NF_ACCEPT. |
| Kernel-conntrack mirror (`publish_conntrack`) | SKIP | SKIP | Mirror covers AF_XDP sessions ONLY (r6-delta C44). Kernel sees re-injected traffic as fresh flows in the shared-device zone per M4 inventory; mirroring P-MECH sessions would double-represent them. M4 kill condition guards zone conflict. |
| GRE/WG/IPsec-passthrough DECAP stages (`stage_native_gre_decap`, `stage_wg_decap`, `stage_ipsec_passthrough_check`) | SKIP | SKIP | Outer already consumed by kernel XFRM; re-decap would misparse inner as outer. |
| Link-layer classify (`stage_link_layer_classify`) | SKIP | SKIP | Synthetic Ethernet is trusted-constructed (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:83-85`); L2 validation meaningless. |
| AF_XDP RX/TX descriptor handling | SKIP (slab/queue transport instead, D11) | SKIP | No UMEM descriptors on this path by construction. |
| Slow-path reinject chokepoint (`maybe_reinject_slow_path…`) | SKIP (verdicts route to q0 writer via D11 verdict queue) | SKIP | Different outlet; the q0 writer (not the slow-path chokepoint) owns the commit. |
| MissingNeighbor / neighbor-seed paths | SKIP | SKIP | P-MECH never forwards natively; kernel resolves post-TUN neighbors. Pending-neighbor buffering does not apply (held packet is NFQUEUE-held, not worker-held). |
| Flowless/non-first-fragment L3-only arms (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4516`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4918`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:5073`) | CONSULT (as applicable) | CONSULT | Fragments are refused before worker admission (§3.6); these flowless arms apply only to genuinely flowless non-fragmented shapes that reach the worker (defense in depth, same code). |
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
policy: policy evaluates the POST-DNAT tuple (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2021-2064`); SNAT never precedes policy (permit-gated
alloc). (d) Screen vs session: screen runs even on session HITS (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4335-4336`) — session never exempts
screening. (e) Foreign-hit vs owner-entry: `session_hit_authority` + `foreign_hit_verdict` UNCHANGED
(judge arrival zone's policy for THIS packet; no in-place install overwrite — the documented anti-hijack
rule, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/session_hit_authority.rs:78-84`). (f) Go pre-gate vs Rust verdict: Rust authoritative; Go-pass +
Rust-refuse = counted divergence, terminal DROP (never Go-override).
q0 failure cleanup (FORWARD): session/NAT allocations are PROVISIONAL until the single q0 write
linearization. A definitive pre-write/write refusal, stale fence, MTU/rate/queue refusal, or other
definitive failure before that linearization invokes exactly-once rollback for the worker-owned
`session_refs` and NAT undo records. A successful q0 write first commits that handle locally and only
then emits `CompletionWritten`; an ACK timeout/uncertain result therefore means "possibly emitted,
state outcome committed" and is DROP/no-retry, never rollback. No BPF/flow-cache/HA publication occurs
before the local commit. INPUT Option A publishes no session state; Option B MUST specify the equivalent
prepare/finalize rollback before it can claim stateful parity. A session-install rollback failure is E10;
NAT/SNAT rollback failure is E17. Either is DROP/no-retry, never ACCEPT or retry.

### §3.4 Established-hit path + Reject posture

**D19.** Session HIT on an owned frame follows the worker established path verbatim: policy hit-counter
re-count (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:830-899`, incl. the #3706 LocalDelivery exception), #8356/#7212 re-derivations, host-inbound +
junos-host teardown re-checks for LocalDelivery (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1373-1585`), NAT application from the entry (`decision.nat`
— `rewrite_src`/`rewrite_dst` applied to q0 bytes for FORWARD-permit), flow-cache accounting. No P-MECH
fast-path fork.

**D20 (Reject ≡ Deny in V1).** Policy `Reject` (and zone `tcp-rst`-on-deny) maps to SILENT DROP-and-count
+ `policy_reject_as_deny_total` (+ `tcp_rst_suppressed_total` where the zone configures `tcp-rst`). The
physical path synthesizes TCP RST / ICMP unreachable toward the source (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4089-4093`, `deny_reply_and_emit`,
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:176`) — but that reply EMITS via worker TX with proven egress, while a P-MECH reject
would have to originate tunnel-bound (XFRM-encrypted, kernel-routed) traffic from userspace with NO
owned-egress proof. Silent-drop is the fail-closed direction; Junos-reject parity is an explicit V1 scope
cut with a follow-up (G5), NOT a silent equivalence (distinct counters + this paragraph). Flowless deny
stays silent per precedent (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4516-4518`).

### §3.5 Session identity: tunnel discriminator (no aliasing)

**D21.** Same-zone cross-tunnel inner flows MUST NOT share session entries (r5 §2: "multi-tunnel
isolated"; overlapping RFC1918 behind branches is the common enterprise shape):

- The existing `SessionKey` discriminator axis (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/key.rs:65-81`)
  gains `TunnelDiscriminator::Ipsec(if_id: u32)`. The forward/reverse discriminator helper in
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/key.rs:42-62` gains the
  reverse arm; the wire codec in `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/discriminator.rs` gets a fresh `<< 32` tag band beside the existing
  tags, never reusing GRE/PPTP space (#7188 decision-6 discipline). Unknown tags refuse import.
- The discriminator is the immutable config-stable XFRM `if_id` (D1), never peer IP, physical/live
  ifindex, or a zone alone. Go passes STN only as advisory; Rust derives the authoritative value from
  the origin and tunnel-row snapshot. Unknown STN or `if_id == 0` is doubt → DROP. The discriminator
  is carried in forward and reverse keys, so tunnel A and tunnel B with the same five-tuple cannot
  replace or hit one another; a native `None` key is a third identity and must not fall back to A/B.
- **New alias-index seam (the prior design did not have one):** on every forward/reverse session
  install, construct a normalized reply tuple with the discriminator removed and insert
  `(session_handle, Ipsec(if_id) or None, canonical_reverse_key, NAT_reverse_tuple, owner_worker,
  snapshot_generation)` into `reply_alias_index[normalized_tuple]`. Population is atomic with the
  session-table install: publish the forward/reverse key first, then the alias row, or publish
  neither. The worker-local index is synchronously replicated to the shared lookup owner before a
  permit is final; a reverse lookup must not observe a half-published pair.
- Eviction/deletion is one transaction with the session entry (expiry wheel, explicit delete, HA
  import replacement, worker-set drain, and generation retirement all remove the alias row first
  or mark it retired before removing the key). Lookup rejects retired/generation-mismatched rows,
  validates NAT reverse tuple and policy direction, and never resurrects an evicted handle. Alias
  scope is the exact routing domain plus attachment generation; no cross-VRF/RG search is allowed.
- Reply lookup order is: exact worker-local discriminator-aware reverse key, then shared
  `reply_alias_index` for the native/reverse packet. `0` candidates is a native MISS; exactly `1`
  candidate validates owner/generation/NAT/policy and resolves; `>1` is AMBIGUOUS → doubt → DROP,
  `session_alias_ambiguous_total`, and one bounded deny event. There is no deterministic pick.
  A native `None` row participates in collision counting, so a native flow colliding with one or
  more IPsec rows is never silently selected.
- Capacity is bounded: two inline candidates plus a spill list capped at eight per normalized tuple
  (S7/T22 owns final constants); overflow refuses the new install and emits E9 accounting.
  Multiplicity is tested for (a) two IPsec tunnels, (b) IPsec plus native `None`, (c) equal SNAT
  external tuples, (d) HA import/delete, (e) generation retirement, and (f) same tuple in distinct
  routing domains. These are required T22 cells, not an assumption that existing reverse indexes
  solve cross-discriminator lookup.
- Snapshot duplicate-if_id detection remains mandatory: strict commit rejects duplicate IDs; tolerant
  load marks all claimants AMBIGUOUS and stages no permit. Generations separate attachments while
  `Ipsec(if_id)` separates tunnels. Existing `SessionOrigin` values remain `ForwardFlow`/`LocalMiss`;
  post-admission semantics and HA sync stay in the ordinary session universe.

The ordinary `reverse_translated_index` is 1:N (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/mod.rs:29-39,1100-1106`);
it is not this seam. The G5 slice MUST implement and audit the new alias index plus a T22 native-
collision/multiplicity matrix before claiming reverse permits. Alternatives rejected: same-zone
sharing (cross-tenant state/SNAT alias), overloading `routing_domain` (corrupts FIB), and a second
P-MECH table (forked return path and replication).


### §3.6 Fragments: V1 deny-only before worker admission

**D22.** The current Go `FragPool` is bounded by `perFlowCap`, `maxDatagrams`, and
`maxDatagramBytes` (64 KiB) (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/fragpool.go:79-110,114-180`);
completed groups are popped at `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/fragpool.go:319`. It does NOT
provide the r5 design's claimed tombstones or canonical L3 reassembly, and P-MECH does not pretend
otherwise.

**V1 fragment permit boundary.** P-MECH permits no fragmented datagram on either FORWARD or INPUT.
The existing sink/q0 interfaces provide no atomic batch verdict or kernel-reassembly purge primitive
grounded in this tree. N q0 writes or N independent NF_ACCEPT syscalls could partially emit a datagram:
after member k succeeds, member k+1 can fail while the kernel retains the first fragment(s), and later
same-ID fragments could complete them across attempts. A fragment-permit option therefore requires an
explicit atomic batch primitive plus proof and is outside this amendment.

- `receiveQueue` already runs `ClassifyCapturePayload` and validates `IsFragment`/`FragmentKey`/
  `FragmentPiece` before constructing `CaptureFrame` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go:226-241`).
  P-MECH MUST reuse those validated fields, not add a second L3 parser. After `Enqueue` stamps
  `frame.phase` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:336-340`)
  and before `consumeFrames` calls `enqueueFlowLocked`/the existing `FragPool.Insert`
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:383-395,446-454`),
  an enforcing fragment creates/refreshes a bounded `FragmentDenyTombstone` keyed by
  `{family, src, dst, protocol, identification, if_id, capture_generation}`. The tombstone has a
  fixed cap and expiry no later than the capture-generation retirement; a late fragment or name-reused
  same-ID member hits the tombstone before `FragPool`, terminal-DROPs, and increments
  `ipsec_inner_fragment_late_total`. It is a deny tombstone, not a reassembly cache. Shadow creates
  no production tombstone; it records the would-drop and bounded `ShadowLedger` divergence only.
- The current receive path drops `ClassifyCapturePayload`, `FragmentKey`, or `FragmentPiece` errors
  before `CaptureFrame` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go:226-241`)
  with no cause evidence. S9.1 MUST add a bounded pre-frame `DenyEventSink`/counter path there:
  `ipsec_inner_classification_errors_total` for parse/codec failure and
  `ipsec_inner_fragment_metadata_errors_total` for key/piece failure, using the capture queue's
  trusted tunnel/generation attribution when available, otherwise `UNATTRIBUTED_POLICY_ID` and no
  fabricated `CaptureOrigin`. These structural pre-frame errors are always terminal DROP (there is no
  valid frame for shadow evaluation), and sink backpressure increments `deny_event_unavailable_total`.
- Non-fragmented packets retain the normal §3 order. Every enforcing fragment original has one terminal
  DROP and one bounded taxonomy/counter/event path: no late worker completion, partial q0 emission, or
  cross-generation reassembly. Duplicate or byte-identical fragments are all denied in V1; the native
  `FragPool` duplicate semantics are not silently claimed for this pre-pool path.
- A future authorized fragment-permit scope MUST retain the key/cap/expiry/tombstone rules and add
  canonical reassembly plus an atomic batch terminal primitive. Its canonical IPv4 output MUST set the
  final total length, clear MF/fragment offset, and recompute the IPv4 header checksum. Its canonical
  IPv6 output MUST remove the Fragment header, repair the preceding Next Header and Payload Length,
  and bound the extension-header chain before any worker policy. Those semantics are not implemented
  or permitted by V1.

### §3.7 Counter/deny-event points (per stage; Rust worker side)

Screen deny → `screen_drops` + `ScreenPacketInfo` alarm event (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/event_emit.rs:333`); session-install
refusal → `create_drops` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/install.rs:100-104`) + DROP; policy deny → `telemetry.dbg.policy_deny` +
`PolicyDeny` RT_FLOW (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/event_emit.rs:138`); NAT failure → `record_source_nat_failure` + DROP; host-inbound
deny → `host_inbound_denied_packets` + `emit_host_inbound_deny` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/host_inbound_policy.rs:170`);
junos-host deny → policy-deny RT_FLOW (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1570`); zone-gate deny → NEW `zone_gate_*` counters + `PolicyDeny`
with `UNATTRIBUTED_POLICY_ID` (§4.1 — the #9989 unattributed pattern, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:195-198`); generation
fence → `zone_gate_stale_total`; alias-ambiguous → `session_alias_ambiguous_total`. Go side: §4.3–§4.4.

---

## §4 G4: deny path

### §4.1 Event types (reuse first; one justified new reason family)

**D23.** NO new event KIND. P-MECH uses the existing RT_FLOW/`PolicyDeny` codec
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/event_stream/codec/decode.rs:50-52`);
its wire `reason` is a `u8` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/event_stream/codec/rt_flow.rs:100-104`),
not a free-form string. Existing policy and host-inbound reason values remain unchanged
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/event_emit.rs:12`, policy=5 and host-inbound=6). P-MECH allocates the closed contiguous
new-reason band 32–60 (29 values) in the versioned Go/Rust wire contract; the exact assignments are
below. An unknown byte at an event decoder is a version/decode refusal: increment
`ipsec_inner_event_decode_errors_total`, emit the bounded `PMechAlarm{class=VERSION_SKEW}`, and do
not invent a label or alter the already terminal packet verdict. An unknown reason at pre-admission is
E33 refusal/DROP. Neither case becomes a permit.

**Bounded event/alarm sink.** `DenyEventSink` is the single bounded daemon-side source for P-MECH
pre-dispatch deny events and operator alarms; Rust-side refusals use the same event codec and set the
`event_emitted` outcome bit. Its bounded API is conceptually
`EmitIpsecInnerDeny(IpsecInnerDeny)` plus `EmitPMechAlarm(PMechAlarm)`, where
`PMechAlarm{class, reason, generation, queue_id, tunnel}` has a closed class enum:
`STAGING_SKIP|OWNER_CONTESTED|NODE_WIDE_QUARANTINE|ZONE_AMBIGUOUS|DOMAIN_OVERLAP|WORKER_QUEUE_FULL|
OWNER_UNAVAILABLE|BYPASS_FENCE|FLIP_GUARD|INPUT_COMPLETION|VERSION_SKEW`. The concrete consumer is the
daemon `PMechAlarmConsumer` owned by `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go`;
it updates the pipeline status/alarm witness and forwards the bounded record to the existing operator
collector. Its transition key is `{generation, class, reason, queue_id, tunnel_ifindex}`; a state
transition emits immediately, then `PMECH_ALARM_COOLDOWN=60s` permits at most one repeat per key per cooldown
window. The consumer owns a hard-capped key map (`PMECH_ALARM_KEY_CAP`) with bounded queue and
tunnel dimensions; when a generation leaves ACTIVE/QUARANTINE it evicts all of that generation's
keys, and a monotonic TTL/LRU backstop evicts stale keys. If the cap is reached with no evictable key,
the alarm is bounded-dropped and increments `deny_event_unavailable_total`; terminal DROP remains
authoritative. Tunnel/queue context is only in the event/alarm payload. `DenyEventSink` is REQUIRED
for E2, E21, E23, E34, E35, staging skips, and generation-wide quarantine; sink backpressure
increments `deny_event_unavailable_total` while the terminal DROP remains authoritative. Tunnel
attribution is never a metric label.

| Byte | Symbol | Taxonomy rows / emission |
|---:|---|---|
| 5 | `LEGACY_POLICY_DENY` | E11, E12, E14; existing `PolicyDeny` emitter (V1 Reject is downgraded to DENY) |
| 6 | `LEGACY_HOST_INBOUND_DENY` | E15; existing host-inbound emitter |
| 32 | `ZONE_UNZONED` | E1 |
| 33 | `ZONE_AMBIGUOUS` | E2 |
| 34 | `IFID_UNDERIVABLE` | E3 |
| 35 | `STALE_GENERATION` | E4 |
| 36 | `MISSING_GENERATION` | E5 |
| 37 | `ZONE_ADVISORY_MISMATCH` | E6 |
| 38 | `SCREEN_DENY` | E7 taxonomy symbol; existing `ScreenPacketInfo` alarm remains the emission |
| 39 | `PARSE_ECN` | E8 |
| 40 | `SESSION_ALIAS` | E9 |
| 41 | `INSTALL_ROLLBACK` | E10 |
| 42 | `TCP_RST_SUPPRESSED` | E13 |
| 43 | `NAT_STAGE` | E16, E17, E18, E36 |
| 44 | `HOOK_ROUTE_MISMATCH` | E20 |
| 45 | `DOMAIN_OVERLAP` | E21 |
| 46 | `OTHER_DOMAIN` | E22 |
| 47 | `WORKER_QUEUE_FULL` | E23 |
| 48 | `VERDICT_UNCERTAIN` | E24 |
| 49 | `SLAB_EXHAUSTED` | E25 |
| 50 | `LEASE_EPOCH` | E26 |
| 51 | `SUBMIT_UNAVAILABLE` | E27 |
| 52 | `EVALUATOR_UNAVAILABLE` | E28 |
| 53 | `EGRESS_RESOURCE` | E29 |
| 54 | `FRAGMENT_REFUSED` | E30 |
| 55 | `PROVENANCE` | E31 |
| 56 | `UNSUPPORTED_HOOK` | E32 |
| 57 | `VERSION_SKEW` | E33 |
| 58 | `WORKER_ORPHAN_HA` | E34 |
| 59 | `INPUT_BOUNDARY` | E35, E37 |
| 60 | `NO_ROUTE` | E19 |

The `Taxonomy rows / emission` column is authoritative: shared symbols deliberately aggregate only
where the counter/event row identifies the finer cause. E11/E12/E14/E15 retain legacy bytes 5/6; E7
does not invent a second PolicyDeny event and remains `ScreenPacketInfo`. The wire-version bump/floor
in §5.6 is REQUIRED before any 32–60 reason is emitted; old decoders refuse rather than reinterpret it.
PMechFlipGuard nft terminals do not traverse the event codec: their fixed E26 metric and transition
alarm reason is `FLIP_GUARD`. Only a user-space E26 event bridge, when needed, emits existing
byte-50 `LEASE_EPOCH`; no new wire byte is allocated for the nft guard.

- Rust policy/session/host denials emit `DataplaneEventKind::PolicyDeny` at the existing refusal site,
  with the rule `policy_id` when one exists. Screen denies retain `ScreenPacketInfo` rather than
  inventing a second PolicyDeny emission. Pre-policy/zone/transport failures use
  `UNATTRIBUTED_POLICY_ID` (0, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:172`)
  plus the P-MECH reason byte and an immutable `IpsecInnerDeny` origin/tuple record; existing emitters
  remain the only Rust producers.
- Go pre-dispatch refusals (staging skip, zone unzoned/ambiguous, evaluator unavailable, queue/
  slab/lease/version refusal, fragment metadata/classification error) MUST use a bounded
  `DenyEventSink` bridge owned by the daemon event producer. Its input is
  `IpsecInnerDeny{reason:u8, policy_id, optional tuple, origin:
  ValidatedCapture(CaptureOrigin) | PreFrame{queue_id,tunnel,generation}, generation}`. The
  `PreFrame` variant is explicitly unauthenticated/no-origin: encoding uses
  `UNATTRIBUTED_POLICY_ID`, omits origin/tuple fields that cannot be trusted, and uses only the
  queue/tunnel/generation attribution as bounded diagnostic context. The bridge encodes the same
  existing `PolicyDeny` event kind and reason byte exactly once. If unavailable/backpressured, the
  packet still DROP-and-counts and `deny_event_unavailable_total`/witness alarm records evidence
  loss; no deny is converted to permit and no unbounded log is attempted.
- `PolicyDeny` carries the DENY rule's policy ID for FORWARD zone-pair and INPUT `junos-host`
  decisions (`emit_policy_deny_event`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/event_emit.rs:138`);
  flowless/inapplicable-L4 remains attributed by the existing `SkippedFragDeny` discipline
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:3763-3769`). Alias ambiguity, generation, M3, NAT, transport, and completion reasons
  use ID 0 plus their closed reason byte; tuple attribution is optional and bounded.
- Screen denies retain `ScreenPacketInfo` alarms (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/event_emit.rs:333`), host-inbound retains
  `emit_host_inbound_deny` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/host_inbound_policy.rs:170`),
  and Go/Rust must not double-emit the same terminal. Rate-limited event-stream backpressure is
  counted, never silently treated as successful observation.

### §4.2 Emission points

Rust (worker thread, at the refusing stage — same call sites as native denies): zone gate (D14, in the
D13 entry before pipeline); screen (`stage_screen_check` deny arm); session-install refusal (install
call site); policy (`deny_reply_and_emit` — `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:176` — with reply SUPPRESSED for P-MECH,
V1 scope D20: logs DENY truthfully per the suppressed-reject tests, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/reject_reply_tests.rs:1551+`);
NAT failure (`record_source_nat_failure` site); host-inbound/junos-host (existing emit sites, §3.2);
alias-ambiguous (reverse-lookup ambiguity site, §3.5). Rate-limiting: the existing generated-error /
event-stream backpressure discipline applies unchanged (no P-MECH exemption; event loss under pressure
is counted by the stream, never silent).

Go (`submitEligible`, `Enqueue`, staging, completion resolver): each pre-dispatch refusal calls
`DenyEventSink.EmitIpsecInnerDeny` once in addition to its typed `PipelineStats` counter and witness
label. The sink is bounded and rate-limited; it is not a log-per-drop path. If the sink cannot accept
the record, `deny_event_unavailable_total` records evidence loss while the terminal DROP remains
authoritative. Rust emits only for frames that reached Rust, so the same terminal is never double-counted.

### §4.3 Counters

Rust (all `u64`, per-worker or shared per existing convention; every name here is REQUIRED — a stage
without its counter fails review). Rust owns increments only for causes detected in the worker pipeline:

- `zone_gate_unzoned_total`, `zone_gate_ambiguous_total`, `zone_gate_stale_total`,
  `zone_gate_no_generation_total` (D14/D16 arms).
- `ipsec_inner_input_stateful_without_session_total` (E37; Option A scope-cut refusal for stateful INPUT
  misses until Option B is proven).
- E8 cause counters: `ipsec_inner_parse_drops_total`, `ipsec_inner_ecn_illegal_drops`,
  `ipsec_inner_session_lookup_errors_total`, and `ipsec_inner_session_lookup_recoveries_total`
  (lookup/poison/unavailable; the affected frame still drops while the table recovery is counted).
- E9/E10 cause counters: `session_alias_ambiguous_total`, `ipsec_inner_alias_overflow_total`,
  `ipsec_inner_alias_replication_failures_total`, `ipsec_inner_session_rollback_failures_total`.
- Stage-specific policy/NAT counters (NEVER merged): `policy_reject_as_deny_total`,
  `tcp_rst_suppressed_total`, `ipsec_inner_alg_errors_total`, `ipsec_inner_filter_errors_total`,
  `ipsec_inner_policer_errors_total` (E11), `ipsec_inner_nat_stage_errors_total` (E16), and
  `ipsec_inner_nat_rollback_failures_total` (E17).
- Route/disposition and INPUT mutation counters: `ipsec_inner_noroute_total`,
  `ipsec_inner_routed_local_total`, `ipsec_inner_input_routed_transit_total`,
  `ipsec_inner_input_nat_mutation_unsupported_total` (E19/E20/E36); the transit counter appears once
  here and is incremented only by the Rust worker route/disposition stage.
- `ipsec_inner_syn_cookie_refusals_total` (E37 strict-SYN/syn-cookie stateful miss),
  `ipsec_inner_ha_unknown_total`, `ipsec_inner_worker_retired_total`,
  `ipsec_inner_worker_orphan_reaped_total`, and `ipsec_inner_orphan_provisional_total` (E34).

Go (`PipelineStats`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:171-198`,
actor fields) owns increments only for pre-dispatch, completion, and asynchronous decode causes:
`ZoneGateDrops`, `ZoneGateUnavailable`, `ZoneDivergences` (Go-pass/Rust-refuse),
`ClassificationErrors`, `FragmentMetadataErrors`, `FragmentLate`, `VersionSkews`,
`InputAcceptErrors`, `ShadowUnavailable`, `ShadowDivergences`, and `EventDecodeErrors`.
`EventDecodeErrors` owns `ipsec_inner_event_decode_errors_total` for daemon-side asynchronous event
decoding; Rust does not increment it. `InputRoutedTransit`, `RoutedLocal`, `InputNatMutationUnsupported`,
`NoRoute`, `HaUnknown`, `WorkerRetired`, `WorkerOrphans`, `OrphanProvisionals`, `PolicyDenies`,
`PolicyRejects`, `TcpRstSuppressed`, `AliasAmbiguous`, `AliasReplicationFailures`, `SessionLookupErrors`,
`SessionLookupRecoveries`, `SessionRollbackFailures`, `NatRollbackFailures`, `AlgErrors`, `FilterErrors`,
and `PolicerErrors` in Go status are read-only projections of Rust worker counters/events; Go MUST NOT
increment them a second time. Existing reused Go terminal fields remain:
`ProvenanceMismatches`, `L2Unsupported`, `OverlapRefusals`, `FragmentDrops`, `AdmissionsRefused`,
`Refused`, `Uncertain`, `Stale`, `Cancelled`, `Timeouts`, `LateCompletions`, and `HandoffRefusals`.
Every actor field is exported in the actor witness.
- Reused (existing, no rename): `policy_deny`, per-rule hit counters + `default_counter`
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs`),
  `UNZONED_INGRESS_DENIED`, `host_inbound_denied_packets`, `screen_drops`, `create_drops`,
  NAT per-rule counters + `snat_packets`/`dnat_packets`, `adjudicated_refused`/class counters
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:448-451`),
  `epoch_rejects`, `mtu_dropped_packets`, `rate_limited_packets`, `queue_full_packets`
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath.rs`).


Daemon-level `PMechStagingWitness` (owned by wiring/nft/fence and retained without a capture actor)
owns staging/table/bounded-sink counters: `StagingSkipped`, `SkippedTunnelDrops`,
`BypassWindowDrops`, and `DenyEventUnavailable` (actor-path sink loss is merged into this global
witness). The separate `QuarantineCounterWitness` supplies the authoritative
`GenerationQuarantineDrops` rollup, and `PMechFlipGuardWitness` supplies the authoritative
`ipsec_inner_flip_guard_drops_total{reason=FLIP_GUARD}` rollup; these witness-only fields are not
copied into `PipelineStats`, so actor and no-actor series cannot double-count.

### §4.4 Metrics + witness join

Extend the 2a witness pattern (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/api/metrics_ipsec_capture_10478.go:14-60`) with four sources:
the actor snapshot (`IpsecCapturePipelineStatus`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go:53-65`) gains the
§4.3 actor fields; daemon/installer-owned `QuarantineCounterWitness` (§D1b) remains alive
independently of actor creation and zero-admission permit state; `PMechStagingWitness` carries
pre-frame/staging/fence fields with the same lifetime; and `PMechFlipGuardWitness` carries the
flip-guard counter with the same no-actor lifetime. The collector merges all four sources as
`CounterValue` with the EXISTING label set
(`runID`, `generation`, `permitEpoch` — `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/api/metrics_ipsec_capture_10478.go:22-25`) PLUS a bounded closed `reason`
label for deny families. Witness-only rows use the explicit no-permit sentinel `permitEpoch=0`
(zero is never an authorization); actor rows use the actual nonzero permit epoch, and the collector
deduplicates by `{source, generation, primary_reason, reason_mask, counter_sequence}`. The descriptor
label set remains fixed for every series.
On daemon startup, `QuarantineCounterWitness.Recover` enumerates every inet/bridge guard and
replacement counter plus each retained metadata chain/rule, recovers `{runID, generation,
primary_reason, reason_mask, install_sequence, label_schema}` from the metadata rule's bounded
`Rule.UserData`/stable names or the durable journal (never from nonexistent counter userdata), reads
the current counts, and resumes idempotent detach/rollup under the original `runID`; restart never
resets or double-counts the witness series.
`PMechFlipGuardWitness.Recover` performs the same enumeration and idempotent journal replay for
`xpf_ipsec_flip_guard_hits_*` objects and `PMechFlipCounterJournal`, including a crash between final
read and GC; it preserves the original `runID` and never adds a final delta twice.
`staging_skipped_tunnel_total{reason}` uses only
`IFID_UNDERIVABLE|LINK_LOOKUP|QUEUE_OPEN|OWNER_CONTESTED|DOMAIN_OVERLAP`; the named
`ipsec_inner_skipped_tunnel_drops_total{reason}` and
`ipsec_capture_generation_quarantine_drops_total{reason}` use that same five-value closed enum,
while `ipsec_inner_bypass_window_drops_total{reason}` uses the fixed closed `BYPASS_FENCE` reason
(E34), never a tunnel label. These staging/quarantine/bypass/flip counters are owned by Go
staging/nftables and the bounded witness, not duplicated as Rust worker increments.
`ClassificationErrors`, `FragmentMetadataErrors`, and `FragmentLate` likewise originate in Go
`receiveQueue`/pre-`FragPool`; Rust owns only the worker
causes listed in §4.3. NEVER use raw STN/tunnel names as label values: tunnel attribution belongs in
the tuple-rich event/alarm payload and bounded logs, not metric cardinality. Rust `s5_reinject` stats
block gains only the §4.3 Rust counters under the existing `(run_id, generation, permit_epoch)` join.
Pipeline-stats/metrics naming follows the `ipsecCapture<Name>Total` +
`xpf_ipsec_capture_<name>_total` convention of the existing collector.

### §4.5 Error taxonomy (EVERY failure → DROP-and-count; no silent drops, no permit-on-error)

| # | Failure | Detector | Terminal | Counter | Event |
|---|---|---|---|---|---|
| E1 | Tunnel UNZONED | Go pre-gate / Rust D14 gate | DROP (never submitted / refused) | `zone_gate_unzoned_total` (+Go `ZoneGateDrops`) | `PolicyDeny`/`DenyEventSink`, reason `ZONE_UNZONED` |
| E2 | Tunnel AMBIGUOUS (multi-claim if_id) | Snapshot build (mark) + gates | DROP | `zone_gate_ambiguous_total` | `PolicyDeny`/`DenyEventSink` + `PMechAlarm{class=ZONE_AMBIGUOUS}` |
| E3 | if_id underivable (unknown STN / 0) | Wiring (staging refuse) + gates | DROP | `zone_gate_unzoned_total` (same family) | `PolicyDeny`/`DenyEventSink` + `PMechAlarm{class=STAGING_SKIP}` when staging caused the refusal |
| E4 | Stale config/fib/permit/queue generation | D14 fence + `allows()` + Go `Current()` | DROP | `zone_gate_stale_total` / `Stale` | `PolicyDeny`/`DenyEventSink` |
| E5 | Missing generations on wire | Socket admit (D15a) | Refuse (never queued) | `zone_gate_no_generation_total` | `DenyEventSink` (pre-admission; Go `AdmissionsRefused`) |
| E6 | Zone/Go-advisory mismatch | D14 cross-check | DROP | `ZoneDivergences` | `PolicyDeny`/`DenyEventSink` |
| E7 | Screen deny | `stage_screen_check` | DROP | `screen_drops` | Screen alarm |
| E8 | Session lookup/inner parse/ECN/codec error (poison or unavailable) | Lookup/parse/codec | DROP (frame); table recovers | `ipsec_inner_parse_drops_total` / `ipsec_inner_ecn_illegal_drops` / `ipsec_inner_session_lookup_errors_total` / `ipsec_inner_session_lookup_recoveries_total` | `PolicyDeny`/`DenyEventSink` + recovery counter |
| E9 | Session alias ambiguous or bounded alias overflow (multi-candidate reply) | Reverse/alias resolution (§3.5) | DROP | `session_alias_ambiguous_total` / `ipsec_inner_alias_overflow_total` | `PolicyDeny`/`DenyEventSink` |
| E10 | Session install refused (cap 131072/worker, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/install.rs:152-154`), session-install rollback failure, or alias replication failure | Session install/rollback/alias commit | DROP + session rollback; rollback failure remains DROP | `create_drops` / `ipsec_inner_session_rollback_failures_total` / `ipsec_inner_alias_replication_failures_total` | `PolicyDeny`/`DenyEventSink` |
| E11 | Zone-pair policy DENY, filter/ALG/policer deny | `evaluate_policy_*` / unchanged worker stages | DROP (silent) | `policy_deny` + rule/default counter; `ipsec_inner_filter_errors_total` / `ipsec_inner_alg_errors_total` / `ipsec_inner_policer_errors_total` for stage failures | `PolicyDeny`/`DenyEventSink` (rule-attributed where available) |
| E12 | Zone-pair policy REJECT | `evaluate_policy_*` | DROP (silent V1, D20) | `policy_reject_as_deny_total` + rule counter | `PolicyDeny`/`DenyEventSink` (logs DENY per suppressed-reject precedent `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/reject_reply_tests.rs:1551+`) |
| E13 | `tcp-rst`-on-deny (zone screen option) | Deny arm | DROP (no RST V1, D20) | `tcp_rst_suppressed_total` | `PolicyDeny`/`DenyEventSink` |
| E14 | junos-host policy deny/reject | `junos_host_local_policy` | DROP | `policy_deny` + rule counter | policy-deny RT_FLOW (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1570`) |
| E15 | Host-inbound deny | Host-inbound gate | DROP (silent, session torn down `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1457-1461`) | `host_inbound_denied_packets` | `emit_host_inbound_deny` |
| E16 | Static/DNAT match error or scope failure | Pre-routing NAT stage | DROP | `ipsec_inner_nat_stage_errors_total` | `PolicyDeny`/`DenyEventSink` |
| E17 | SNAT alloc failure (pool exhausted, non-first-frag gate `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3026`, NPTv6 refuse `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3182`) or NAT/SNAT rollback failure | Permit-branch NAT | DROP + release partial; rollback failure remains DROP | `record_source_nat_failure` / `ipsec_inner_nat_rollback_failures_total` | `PolicyDeny`/`DenyEventSink` |
| E18 | NAT64/NPTv6 translation failure | Translation | DROP | existing translation counters | `PolicyDeny`/`DenyEventSink` |
| E19 | Route NoRoute/FIB miss | Route/FIB resolve | DROP (doubt) | `ipsec_inner_noroute_total` | `PolicyDeny`/`DenyEventSink` |
| E20 | Hook/disposition mismatch (FORWARD resolves `LocalDelivery`; INPUT resolves transit/`FabricRedirect`/non-local) | Route/disposition check (§3.2) | DROP (doubt; never switch hooks) | `ipsec_inner_routed_local_total` / `ipsec_inner_input_routed_transit_total` | `PolicyDeny`/`DenyEventSink` |
| E21 | Inner-prefix overlap admitted (M3 violation observed) | M3 admission/commit checks | Tunnel DOWN + DROP | `nfq_reentry_unsupported_domain_total` (r6 §3.5 item 6 name — REUSED, not reinvented) | `PolicyDeny`/`DenyEventSink` + `PMechAlarm{class=DOMAIN_OVERLAP}` |
| E22 | Other-VRF/RG/FIB packet at admission | M3 expected-domain stamp + route/disposition/commit revalidation | DROP | `nfq_reentry_unsupported_domain_total` | `PolicyDeny`/`DenyEventSink` |
| E23 | Worker ingress queue full | D11 enqueue (try-or-drop) | DROP | `ipsec_inner_worker_queue_full_total` | `DenyEventSink` + `PMechAlarm{class=WORKER_QUEUE_FULL}` |
| E24 | Verdict queue full / verdict lost | D11 verdict path / `ackDeadline` | Uncertain → DROP, no retry | `ipsec_inner_verdict_queue_full_total` / `Uncertain`+`Timeouts` | `DenyEventSink` + terminal accounting |
| E25 | Slab pool exhausted | Socket admit (D15b) | Refuse | `ipsec_inner_slab_exhausted_total` | `DenyEventSink` (Go `AdmissionsRefused`) |
| E26 | Lease/permit/epoch failure (closed, stale, mismatch, echo-mismatch, shutdown/cancel, handoff race), or any PMechFlipGuard terminal DROP during the guarded transition | `MintLease`/`allows()`/submit gate/echo check / `PMechFlipGuard` | Refuse/Uncertain → DROP | `Stale`/`Cancelled`/`Uncertain`/`AdmissionsRefused` / `ipsec_inner_flip_guard_drops_total{reason=FLIP_GUARD}` with persistent `PMechFlipGuardWitness` rollup | User-space E26: `DenyEventSink` with wire reason `LEASE_EPOCH`; nft flip guard: transition `PMechAlarm{class=FLIP_GUARD,reason=FLIP_GUARD}` plus terminal accounting |
| E27 | Submitter unavailable, socket down, `submitGate` cancellation race, or staging queue-open failure (`QUEUE_OPEN`) | `submitEligible` / socket client / staging | Refuse/Uncertain → DROP | `Refused`/`Uncertain` / `StagingSkipped` (existing `ErrNoSubmitter`) | `DenyEventSink` + `PMechAlarm{class=STAGING_SKIP}` when staging caused it |
| E28 | Evaluator unavailable (nil evaluator, nil/stale snapshot, or unavailable authoritative worker set) | Go pre-gate / Rust evaluator authority (D9/D16) | DROP (enforcing) / `shadow_unavailable` + ACCEPT (shadow) | `ZoneGateUnavailable` / `ShadowUnavailable` | `DenyEventSink` + witness labels |
| E29 | FORWARD q0 MTU/queue/rate failure or a definitive INPUT **pre-committer** resource refusal with explicit `{InputCommitInvalid, TerminalAttempted: TerminalAttemptNo}` and one retained-handle DROP (only before `InputPermitCommitter` entry) | `submit_adjudicated_frame` / pre-committer Go adapter and q0 sink | Refuse/definitive-DROP → DROP | `mtu_dropped_packets`/`queue_full_packets`/`rate_limited_packets` / `ipsec_inner_input_accept_errors_total` | `DenyEventSink` + terminal accounting |
| E30 | Validated fragment metadata on P-MECH path OR pre-frame classification/key-piece error | Receive classification + pre-FragPool phase gate (§3.6) | Validated fragment: ENFORCING DROP exactly once; SHADOW would-drop/divergence + ACCEPT. Pre-frame error: DROP in both phases (no valid frame exists) | `FragmentDrops` / `ClassificationErrors` / `FragmentMetadataErrors` / `ipsec_inner_fragment_late_total` | `DenyEventSink` (pre-frame uses `PreFrame`/unattributed origin) |
| E31 | Provenance mismatch / unregistered queue | `Enqueue` | DROP (never q0) | `ProvenanceMismatches` (existing) | `DenyEventSink` |
| E32 | Non-inet or unsupported hook at submit (bridge is quarantine; inet/input is supported) | `submitEligible` family/hook gate | DROP | `L2Unsupported` (existing) | `DenyEventSink` |
| E33 | Version skew, unknown admit/reason/tag, missing tunnel row, or mixed-version wire | Exact-equality gates (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go:327,343-389`) | Refuse snapshot / DROP | `VersionSkews` + existing version-gate counters | `DenyEventSink` + operator-visible abort |
| E34 | Owner-worker down, worker-set retired, unknown HA attachment, HAInactive/redirect, punt-seed, preemptive/post-detection bypass-fence drop, orphan descriptor, or verdict-issued provisional handle | Router/fence/reaper/journal and HA decoder | DROP (never misroute; no redirect/punt; reaper terminalizes orphans; journal conservatively commits write-started state) | `ipsec_inner_worker_retired_total` / `ipsec_inner_worker_orphan_reaped_total` / `ipsec_inner_orphan_provisional_total` / `ipsec_inner_ha_unknown_total` / `ipsec_inner_bypass_window_drops_total` | `DenyEventSink` + `PMechAlarm{class=OWNER_UNAVAILABLE|BYPASS_FENCE}` |
| E35 | Invalid/mis-scoped `CompletionInputReady` (non-inet/input, nonzero bytes except exact INPUT exemption, duplicate/late, or terminal identity mismatch), any post-committer pre-syscall validation error (`ErrClosed`, unsupported verdict, already-verdicted/duplicate/wrong-queue), post-committer `q.mu` lock-acquisition timeout before any fd syscall, or ANY error after fd-syscall entry (EAGAIN/timeout or other) on `Packet.Verdict`/`VerdictBatch` | Go completion resolver / worker outcome codec / `InputPermitCommitter` / nfqueue `q.mu` and fd send | DROP/uncertain | `ipsec_inner_input_accept_errors_total` + `Uncertain`/`Timeouts` | `DenyEventSink` + `PMechAlarm{class=INPUT_COMPLETION}` |
| E36 | INPUT product NAT would rewrite or cross-family translate (NF_ACCEPT cannot replace payload) | Decision-only NAT consult | DROP (before policy/route) | `ipsec_inner_input_nat_mutation_unsupported_total` | `PolicyDeny`/`DenyEventSink` |
| E37 | INPUT stateful miss outside authorized D12a Option A, strict-SYN/syn-cookie new-flow miss, or session-required shape | D12a session boundary | DROP before NF_ACCEPT | `ipsec_inner_input_stateful_without_session_total` / `ipsec_inner_syn_cookie_refusals_total` | `PolicyDeny`/`DenyEventSink` |

Coverage claim: arms D16.1–9 ⊂ {E1–E37}; generation-wide `QuarantineAll` drops map by closed reason to E3/E27/E2/E21 as D1b specifies, and preemptive/post-detection bypass-fence drops map to E34. Every `resolveRefusal`/`resolveUncertain`/terminal-DROP call site
in `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go` maps to exactly one row; every Rust refuse path maps to exactly one row. The G5 slice
MUST include a mechanical audit (grep every `VerdictDrop`/refuse/uncertain emission on the S5 path against
this table and the closed quarantine/fence reason map; unmapped emission = review failure). No row maps to permit, ACCEPT (except shadow-divergence
ACCEPT per §2.6 matrix), retry, or silence. `CompletionInputReady` is non-terminal and is covered by
E35 on any malformed or mis-scoped use; E36 covers product-NAT mutation; E37 covers stateful INPUT
misses when Option A is the only authorized scope.

### §4.6 Alternatives rejected (G4)

- New `TunnelZoneDeny` event kind: REJECTED. New kinds fork every consumer (codec, decoders, dashboards,
  retention). The #9989 unattributed pattern (`UNATTRIBUTED_POLICY_ID` + dedicated counters) exists FOR
  pre-policy denies — reuse it.
- Direct/unbounded Go-side dataplane deny emission: REJECTED. The bounded daemon `DenyEventSink` bridge
  required by D23 is accepted for pre-dispatch/pre-frame attribution; it emits the existing `PolicyDeny`
  codec once with a closed reason and records backpressure as `deny_event_unavailable_total`. Go still
  does not grow a second event kind, per-drop logger, or unbounded producer; counters + witness labels
  remain the evidence surface when the bounded bridge is unavailable.
- Log-per-deny: REJECTED. Rate-bounded telemetry only (r5 H1); per-drop logging is a DoS amplifier.
- Merging limitation counters into one generic drop count: REJECTED. r5 N5 (`/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md:645-651`) explicitly pins
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
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/nfqueue.go` — every fd-send path
  (`Packet.Verdict` and `VerdictBatch`/`sendmmsg`) MUST use bounded/nonblocking `q.mu` acquisition
  together with `SOCK_NONBLOCK`/`SO_SNDTIMEO`; the close/rebind path proves no `q.mu` deadlock,
  performs generation-level queue recovery, and uses queue-wide close only as the fenced, accounted
  teardown after EAGAIN/timeout, never per-packet cancellation.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go` —
  receive-time tunnel attribution (D8 secondary) + status snapshot fields (§4.4) +
  signed `PMechShadowBudget` storage/validation input + `PMechAlarmConsumer`/bounded
  `DenyEventSink` bridge with `PMECH_ALARM_COOLDOWN=60s`; actor-path sink loss merges into the global
  staging witness.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go` —
  per-generation if_id→zone map build (§1.1) + config/fib generation capture at staging (D13) +
  duplicate-if_id detection (§3.5) + snapshot publication (D9) + explicit `QuarantineAll`/deny-only
  activation + durable `QuarantineCounterJournal` and `PMechStagingWitness` storage.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/reinject_socket.go` — wire:
  generations and per-frame descriptor identity on submit (D13/D15); unknown admit-reason ⇒ refusal
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/routing/routes.go` and
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/routing/routing.go` —
  main-table-254 forwarding inventory across all installed route protocols, ECMP `NextHops` ownership,
  explicit/legacy selector intersection, frozen per-tunnel `ingress_prefixes` membership enforcement,
  partial/unresolved refusal, and generation joins.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_reinject_supervisor.go` —
  typed `InputPermitCommitOutcome`, queue-generation fencing, bounded committer close/recovery, and
  supervisor status/verifier hooks for INPUT completion.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_topology_owner_9506.go` —
  failover actuator and status field `FailoverRefused`/`PMechAdmission=DENY_ONLY`; `PMechFailoverVerifier`
  checks peer protocol/floor/tag equality, worker-set generation, fence, and transit-barrier readiness
  before OPEN; sole `PMechFlipAuthorizer` verifies the signed budget, owns the seven-step `PMechFlipGuard`
  state machine, and publishes its status/witness before final OPEN.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_host_fence_reconcile_9506.go` (+
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_supervisor_loop_9506.go` caller) —
  the shared OPEN predicate at `tryOpenIpsecPermitAfterFenceAck`/`tryOpenPermit`: SAFE-topology/fence ACK
  AND NOT `FailoverRefused`/`PMechAdmission=DENY_ONLY` AND generation-bound `PMechFlipAuthorizer` approval
  for P-MECH generations (step-7 CAS is the sole opener; ordinary fence reconciliation MUST NOT bypass
  refusal or an incomplete flip).
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/api/metrics_ipsec_capture_10478.go` (+
  collector decls) — §4.4 actor/staging/quarantine/flip-guard witness merge, fixed
  `(runID,generation,permitEpoch,reason)` labels, and `permitEpoch=0` no-permit sentinel.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/xfrmi.go` — exported
  `BindInterfaceOwnsRef` wrapper over the existing ownership predicate; this is the config SSOT used
  by staging and the D14 zone gate.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/ipsec/policy.go` — shared
  `effectiveTrafficSelectors`/selector provenance source for M3, including valid legacy
  `RemoteID`/`LocalID` fallback and explicit-vs-implicit `0/0` distinction.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/logging/ringbuf.go` — extend the existing
  `closeReasonName` decoder (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/logging/ringbuf.go:1297-1316`)
  with the closed P-MECH reason/severity mappings; lockstep decoder tests remain in the owning package.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nftables/ipsec_divert.go` — explicit
  `QuarantineAll`/guard rendering on separate inet/bridge base-chain tables, two-family ACK/readback,
  named family/hook counters, `PMechFlipGuardWitness`/`PMechFlipCounterJournal` recovery,
  quiesce/final-read/fsync/GC lifecycle, and replacement failure/bridge-degraded refusal.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go` —
  REQUIRED protocol-floor/tunnel-row/admit-reason contract and version bump (never conditional).
  Its exact Rust lockstep counterparts are also REQUIRED:
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/protocol/control.rs`
  (version/equality gate and control wire) and
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/protocol/snapshot.rs`
  (snapshot DTO/wire fields). A mismatch is E33, not a decode default.

Rust (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/`):

- N `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/ipsec_inner.rs` (worker entry D13 + zone gate D14 + verdict post) + N `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/ipsec_inner_queue.rs`
  (D11 per-worker ingress queues + slab pool + verdict queue + poll-budget drain) — NEW files (no
  suitable existing owner; adjacent to `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/gre.rs` and `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/wg/decap.rs` precedent).
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs` —
  exact worker stage order, decision-only flow-cache/DNS handling, syn-cookie/challenge suppression,
  strict-SYN route-eligibility, HAInactive/punt guards, and E7/E11–E20/E34/E37 deny arms.
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
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/lookup.rs` and
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/mod.rs` — bounded
  cross-discriminator alias index, multiplicity/eviction/generation checks, and ambiguous reverse
  refusal (D21; `reverse_translated_index` remains separate).
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/worker/loop_body/mod.rs`
  and `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/worker_queue.rs` —
  reuse the one immutable tick `RuntimeView` binding in the actual poll body, D11 bounded
  drain/verdict post, orphan-reaper handoff, and `WorkerCommand` generation/worker-set control
  variants only (D12); setup publication is not a separate P-MECH ownership item.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs` — NOTHING
  (evaluation reused; D20 Reject≡Deny is a P-MECH deny arm, not a default-policy change). If truthful
  REJECT logging needs a flag, add only a call-site parameter.
- M `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/event_emit.rs`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/event_stream/codec/rt_flow.rs`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/event_stream/codec/decode.rs`,
  and `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go`
  — closed u8 reason map, Rust emitters, and the bounded Go `DenyEventSink` bridge (§4.1–§4.2).

Tests (in-file + existing suites; no new harness): unit cells per §5.3; the G5 slice owns its cells +
affected-suite numbers; NO harness file (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/test/incus/*`) is
touched (O-*/V-FLIP own those).

### §5.3 Slice order (within P-MECH; each step reviewable, fail-closed at every intermediate)

1. S9.1 Go pre-gate + wiring (map build, staging capture, `submitEligible` site, stats, metrics) with
   Rust stubbed to refuse-all-new-codes (proves Go fail-closed standalone; live-proves denied-only).
2. S9.2 Rust transport (queues + pool + verdict path + admit codes) with worker entry stubbed to
   deny-all-with-reason (proves plumbing + taxonomy E23–E25/E34 standalone).
3. S9.3 Worker entry + zone gate + generation fence (D13–D14; proves E1–E6/E33 with datagram verdicts).
4. S9.4 Session discriminator + pre-worker fragment refusal (D21–D22; proves E9–E10/E30,
   classification/key-piece counters, enforcing DROP, and shadow divergence+ACCEPT without `FragPool`).
5. S9.5 Full stage consultation + NAT mutation + q0 join (D17–D20; proves E7/E11–E20 and FORWARD
   permitted flows). INPUT `CompletionInputReady`/supervisor commit is wired only for the D12a Option A
   stateless shapes after proof cells `D12a-C1` (ICMP/ICMPv6 skip-install + reply deliverability) and
   `D12a-C2` (T5 host-bound disposition for both verdicts); all stateful INPUT misses remain E37.
   Option B is deferred.
6. S9.6 Deny-path completion + taxonomy audit E1–E37 (§4.5 coverage proof) + metrics/witness join.
7. S9.7 Live-proof gate (§5.4) + kill conditions (§5.5) + M1–M4 must-prove evidence (or authorized
   scope cuts).

### §5.4 Validation bar (MUST all hold; any fail = slice kill or authorized scope cut, §1.6)

- Unit cells (fail-on-revert): zone map (zoned/unzoned/ambiguous/cross-spelling/duplicate-if_id/stale);
  Go hook (pass/drop/nil/stale/shadow-matrix); typed reason/zero-value refusal; admit codes (each new
  code + unknown-code-refusal); supervisor committer result matrix (invalid/unknown/accepted/dropped/
  uncertain; `Accepted+error`, `Dropped+error`, unknown result, explicit `terminalAttempted` true/false,
  stale-after-lease, sink-failure, and timeout); only pre-committer `terminalAttempted=false` may
  use the retained handle for one DROP, while any post-entry inconsistency is uncertain with no retry
  or second sink call; route-domain identity (exact `D_usp1`/main-table
  result, other-domain refusal, commit revalidation); discriminator (forward separation, reverse
  unique/ambiguous/native-miss, wire round-trip, unknown-tag import refusal); fragments (validated
  metadata bypasses `FragPool` and is E30: enforcing DROP exactly once, shadow would-drop/divergence +
  ACCEPT; pre-frame classification/key-piece errors DROP in both modes with pre-frame counters/events);
  taxonomy fault-injection/unit/integration cells (each E-row fires its counter/event once, including
  poison/recovery, rollback, slab, mixed-version, unknown-tag, and orphan phases; no unmapped terminal
  emission — mechanical audit §4.5);
  stale-fence and fabricated-zero refusal; doubt arms D16.1–9 (each → DROP, never permit).
- Additional contract cells: no fragment frame enters worker/session/NAT/q0, no duplicate parser is
  introduced, and pre-frame `DenyEventSink` `PreFrame` attribution is unattributed/queue-bounded;
  `ProvisionalJournal` CAS recovery for Prepared/WriteStarted/Committed worker-crash phases; shadow
  queue-full/dead-worker/timeout/stale-drain result tombstones plus refcount/hazard completion ACK,
  proving no early ShadowSlab reuse or production session/NAT/flow-cache/HA/counter mutation;
  INPUT and FORWARD slab release is exactly once on deny, queue-full, worker death, timeout, stale
  drain, and late completion. The INPUT committer cell stalls both scalar `Packet.Verdict` and a
  preceding `VerdictBatch` send, forces a post-entry `q.mu` lock timeout with no fd syscall to
  `{InputCommitUncertain, TerminalAttempted: TerminalAttemptNo, Err: q_mu_timeout}` with no
  retained-handle DROP fallback and no retry, and maps any attempted-send error after fd-syscall entry
  (EAGAIN/timeout or other) to `{InputCommitUncertain, TerminalAttempted: TerminalAttemptYes}`,
  maps a pre-committer invalid outcome with explicit `TerminalAttemptNo` to definitive E29 plus one
  retained-handle DROP, and maps every post-committer `ErrClosed`, unsupported-verdict,
  already-verdicted, duplicate, or wrong-queue validation to E35 uncertain with no retry (even when
  no fd syscall occurred). It proves every fd-send path is bounded/nonblocking and proves fenced
  queue-epoch recovery (fence, CAS held to uncertain, single `Queue.Close`/rebind census) with no
  `q.mu` deadlock.
- Shadow flip cells verify one signed `PMechShadowBudget`/`PMechFlipAuthorizer`, `T_shadow_max` expiry,
  flood deferral, two-family guard ACK/readback, baseline-ACCEPT drain with late-result tombstones,
  exact-once `FLIP_GUARD` E26 DROP counters on the designated family/hook owner, and
  `PMechFlipGuardWitness` final-read→fsync→GC/restart idempotence. Permit stays CLOSED through
  RuntimeView publish and both guard removals; only step-7 CAS opens it. Partial-removal failure
  keeps CLOSED and restores a two-family guard before recovery; a post-activation failure
  installs/ACKs a fresh guard before active-epoch drain/replacement.
  Flow-cache rows missing discriminator/generation and DNS fastpath INPUT-miss behavior both refuse,
  never permit.
- OPEN-gate race cells: ordinary fence reconciliation racing a live `FailoverRefused`/`DENY_ONLY`
  status or an incomplete flip (missing approval, guard ACK/removal, or step-7 CAS) never opens;
  the shared predicate at `tryOpenIpsecPermitAfterFenceAck` is the sole opener and every losing
  race stays CLOSED/deny-only with reason evidence.
- Staging/quarantine parity cells: each closed skip reason (`IFID_UNDERIVABLE`, `LINK_LOOKUP`,
  `QUEUE_OPEN`, `OWNER_CONTESTED`, `DOMAIN_OVERLAP`) maps to E3/E3/E27/E2/E21; simultaneous skips
  retain a bounded `QuarantineReasonMask` and deterministic primary precedence, while each reason
  counter remains attributable. A skipped-ifindex emits an nft DROP+counter rule; zero admitted
  handles emits deny rules for every staged candidate, and both inet/bridge families require
  `QuarantineInstallAck` or the cell is PLAN-KILL. The cell fences/drains old permits/descriptors
  after guard ACK, exercises quarantine activation 3A and recovery 3B (including quarantine→quarantine
  rotation), and verifies guard/replacement counter quiesce→ACK→final-read→fsync→GC and crash
  restart idempotence without double-counting. The fsynced journal record persists `primary_reason` +
  `reason_mask`; a dedicated restart-after-counter+metadata-GC cell deletes both objects, recovers the
  witness series and `{source,generation,primary_reason,reason_mask,counter_sequence}` dedup key from
  the journal alone, and proves no loss, misattribution, or double-add. `T12_delete_recreate_name_reuse`
  and `T12_tolerant_load_parity` are named cells; old-spec failure never reuses an authority.
- D22 cells: bounded tombstone cap and expiry at generation retirement; late fragment/name-reuse
  refusal and `ipsec_inner_fragment_late_total`; duplicate/byte-identical fragment denial; no
  `FragPool` entry in either phase. The P-MECH entry reuses the tick's one immutable `RuntimeView`
  binding with zero new `load()` calls (canary-guarded); refresh interleaving refuses; the
  DNS/flow-cache helpers cannot recycle, TX, or seed production state.
- Affected suites + reverse-deps with numbers (run at slice end; parent validates project-wide).
- THE live run (loss cluster, real SAs — MATCH-gated attestation): representative denied AND permitted
  FORWARD v4+v6 decrypted-ingress flows with policy/session/counter/event evidence (FORWARD→q0→fence
  delivered witness). INPUT live evidence is conditional on the two D12a Option A proof cells:
  D12a-C1 ICMP/ICMPv6 skip-install + reply-deliverability and D12a-C2 T5 host-bound disposition for
  both verdicts. Only the proven stateless shapes may claim `CompletionInputReady`→supervisor
  `InputPermitCommitter`→NF_ACCEPT, never q0; all stateful INPUT remains E37 and Option B is deferred.
- Live deny coverage is by UNION across hooks; the exhaustive E1–E37 claim belongs to the
  fault-injection/unit/integration cells above, not to a safe live-SA run. Each hook independently
  exercises the shared ingress families `ZONE_UNZONED`, `ZONE_AMBIGUOUS`, `SCREEN_DENY`,
  stale-generation, fragment-deny (validated metadata plus malformed classification/key-piece error),
  alias ambiguity, and transport refusal. FORWARD-specific mandatory live cells are zone-pair policy
  DENY/REJECT, DNAT/SNAT/NAT failure, NoRoute, route/disposition mismatch, queue/q0/MTU, NAT-T +
  native, and multiple tunnels (including the same-zone overlap pair for D21 + M3). INPUT-specific
  mandatory live cells are host-inbound deny, `junos-host` deny, product-NAT mutation E36,
  `LocalDelivery`/non-local E20 guard, exact `CompletionInputReady` invalid/accepted/uncertain
  outcomes, and the D12a-C1/C2 proof shapes. Scale spots remain 8/16/32 tunnels; a hook does not
  claim a branch it cannot reach.
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
  pre-frame classification/key-piece event bridge and fragment-deny path are priced line items, not hidden
  costs; V1 claims no fragment concat/reassembly allocation). Kill: T22 miss on the loss cluster
  (K4 honors itself).
- M1–M4 evidence (or authorized scope cuts recorded in the sign-off, §1.5–§1.6). K-M5a: §3.5-item-2
  coupling proof-or-split cell (G1/T8) — owned by S4/S7 but REQUIRED before P-MECH's permitted-flow
  claims are valid under delegated load (a coupled q0 refusal under flood must be proven within
  overload-shed budget, else DROP-and-count the coupled class per §3.5 item 2).


### §5.5 Kill conditions

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
- K-P8: either named proof cell `D12a-C1` (worker skip-install/reply deliverability) or
  `D12a-C2` (T5 host-bound disposition) fails, or any stateful INPUT miss is accepted without the
  required session atomicity. On a failed proof cell the permitted INPUT shape is narrowed to the
  proven subset or removed; stateful acceptance is a P-MECH PLAN-KILL (not a silent stateless
  widening).

- K-P9: any shadow execution mutates production session/NAT/flow-cache/HA/counters, shares a
  production verdict transport, or cannot prove bounded `ShadowLedger` isolation. Shadow is then
  forced to `shadow_unavailable`/disabled; if the owner requires shadow evidence and the isolation
  cannot be restored, P-MECH is PLAN-KILLED rather than running side effects.
- K-P10: `ProvisionalJournal` cannot recover every `Prepared`/`WriteStarted`/`Committed` handle with
  one CAS terminal and bounded expiry/reconciliation, or a worker crash causes blind rollback after
  a possible q0 write. The affected permit class is DROP-only until fixed; no leak or misdelivery
  is accepted.
- K-P11: S4 does not prove a continuously present preemptive master/VRF fence matching every future
  master, or the implementation treats pre-detection exposure as bounded by `T_census_max`; the
  measured post-detection fence ACK exceeds `T_fence_ack_max=100ms` or is unmeasurable; or any
  bypass permit exists while ownership/fence state is unresolved. Any such result is PLAN-KILL, not
  a latency-tuning task. The validation cells in §5.4 must show preemptive-fence presence/future-master
  coverage, detection→ACK measurement, and bypass-fence drops mapped to E34.
- K-P12: the signed `PMechShadowBudget`/sole `PMechFlipAuthorizer` is missing, duplicated, expired,
  or bypassed; `FloodDeferralGuard` is bypassed; either family lacks flip-guard ACK/readback or
  removal proof; the permit is not CLOSED through steps 3–6 or opens before both removals are
  acknowledged; `FLIP_GUARD` E26 counters/witness are not exact-once and restart-persistent; or a
  post-activation failure drains/replaces the active epoch before a fresh two-family guard is
  installed and ACKed. Before step 1, an unmet eligibility condition remains observational Shadow
  pass-through or an explicitly owner-selected deny-only state, never OPEN. After step 1 installs
  the guard, any listed transition failure remains deny-only; if the guard, witness, or proof cannot
  be restored and proven within bounded recovery, the design is PLAN-KILLED. K-P12 is exercised by
  §5.4 Shadow flip cells and the full seven-step protocol in §5.7.

### §5.6 Mixed-version and rolling-upgrade procedure

P-MECH's tunnel-row fields, `Ipsec(if_id)` discriminator tag, `CompletionInputReady` fields, and
u8 deny-reason range are one wire contract. The current dataplane `ProtocolVersion` is 28
(`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go:327`);
the design target is **29**, implemented as a new immutable `MinProtocolPMech = 29` floor plus the
P-MECH tunnel-row/admit-reason floors at
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go:343-389`.
The Rust lockstep codec is `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/protocol/control.rs`
and `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/protocol/snapshot.rs`.
Go and Rust are either lockstep-compatible (exact version, tunnel rows, and all P-MECH floors match)
or they use this deny-only drain procedure:

1. Put the retiring side in deny-only mode: fence new P-MECH capture admission, stop minting permits,
   and publish the retirement generation. Do not let a new decoder consume an old descriptor.
2. Upgrade the HA standby FIRST by keeping its old Go/Rust binaries and codecs alive while it fences
   new admission, drains every old-version descriptor under the old codec, and retires its old
   worker-set generations/slabs/alias rows only after the drain witness. A timeout or missing worker
   is E24/E34 DROP-and-count, never a retry through a new decoder.
3. Replace the standby Go protocol mirror, Rust snapshot/control codec, `Ipsec(if_id)` discriminator,
   tunnel rows, and closed reason map. Apply the new snapshot only after exact version/floor equality,
   worker-set generation, and a standby fence/status witness; do not activate capture yet.
4. Perform the same fence→old-codec drain→retire sequence on the active side, then upgrade/publish
   the new codec, tunnel rows, reason map, and discriminator floor. Verify exact generation/protocol
   equality and the new transit barrier on both sides before activating capture queues.
5. For an unplanned failover, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_topology_owner_9506.go`
   invokes `PMechFailoverVerifier`. Missing peer floors/tags, protocol 29 equality, worker-set generation,
   transit-barrier/fence readiness, or a status witness sets the status API field
   `FailoverRefused`/`PMechAdmission=DENY_ONLY`, leaves the node fenced, and forbids OPEN. The verifier
   and live status read must show the new snapshot, tunnel-row floor, worker-set generation, fence, and
   transit barrier before activation.

Downgrade/rollback is symmetric and never mixed-version: stop new admission, fence the new generation,
drain all new descriptors under the new Go/Rust codec pair, retire its workers and aliases, then restore
the old Rust control/snapshot codec and workers first while still fenced; verify the old Rust generation
and descriptor drain. Restore the old Go protocol mirror/actor/wiring snapshot second, verify exact old
Go↔Rust equality and the old fence/status witness, and remain deny-only until that verifier passes.
Because the old side lacks P-MECH tunnel rows/reason fields, rollback MUST NOT consume a new tag or
permit a P-MECH frame; any old/new mismatch stays deny-only.
If an old side receives a new HA session tag, its
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/discriminator.rs`
decoder yields `WireDiscriminator::Unrecognized`/absent, maps to E33, and refuses import.

Any mixed-version frame, unknown admit/reason/tag, missing tunnel row, or old descriptor arriving
after the fence is E33 → DROP-and-count. There is no best-effort decode, default reason, or permit
during a version mismatch. The drain/activation witness is a prerequisite to S9.7 permitted-flow
claims; if it cannot be bounded, P-MECH remains deny-only or is PLAN-KILLED.
### §5.7 Shadow-to-enforcing flip protocol

Shadow is an **observational pass-through** phase, not deny-only: the existing Go call site
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:383-428` owns the baseline
`finishFrame(frame, VerdictAccept)` for the held frame. The Rust shadow evaluator observes a bounded
copy/result and cannot authorize, deny, or otherwise change that in-flight terminal. Install each
generation in shadow with immutable `phase=Shadow`, generation, hook, tunnel-owner authorization,
and `observed_permit_epoch` captured in every descriptor; this field is read-only evidence, never an
authority token. Shadow carries no production lease, request ID, session/NAT/flow-cache/HA row,
production dataplane counter, or verdict; its bounded would-drop/divergence/unavailable counters
live only in `ShadowLedger`/witness. The bounded shadow transport is the one in D11/D12a, not the
production verdict queue. `shadow_unavailable` therefore preserves the Go-owned ACCEPT baseline,
exactly as §2.2/§2.6 require; it MUST NOT silently become enforcing or deny-only.

Every candidate generation has a signed `PMechShadowBudget` containing numeric
`max_duration=T_shadow_max`, numeric `max_divergence`, numeric cumulative `max_accepted` (total
Shadow baseline-ACCEPT terminals allowed for the generation), exactly one `signer_identity`,
generation, runID, and
`budget_file=/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go:PMechShadowBudget`.
The sole `PMechFlipAuthorizer` identity (owned by
`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_topology_owner_9506.go`) verifies
that signature against the owner-provisioned trust anchor (pinned authorizer key in the topology-owner
config; unknown-signer or unsigned budgets are ineligible, never default-accepted). `T_shadow_max` bounds
eligibility: if criteria are not met by expiry, the generation is drained and replaced by a new
signed Shadow generation or remains deny-only; it is never eligible indefinitely. Breaching
`max_divergence` or cumulative `max_accepted` before step 7 is a budget breach: remain in Shadow
pass-through or enter deny-only, never open. Numeric values for `T_shadow_max`, `max_divergence`,
and `max_accepted` are an explicit OWNER DEFERRAL: they depend on the loss-cluster traffic profile
only the owner can measure, so G5 ships the fields, signature/anchor verification, expiry/cap
enforcement, and K-P12 kill polarity, with owner-supplied values recorded at install sign-off.

Flip eligibility requires the shadow generation to be quiesced and drained:
`shadow_unavailable=0`, every required hook/tunnel has an owner-authorized shadow result, divergence
is within the signed numeric budget with no unknown reason, all §5.4 `D12a-C1`/`D12a-C2` and M1–M4
cells attach to the same generation, and the deny/event/counter witness has no loss. A
`FloodDeferralGuard` blocks the flip while any queue/poll backlog, outstanding shadow descriptor,
overload-shed state, or worker drain is nonzero; it waits for the bounded low-watermark before
starting the sequence and defers (or expires) rather than flipping under flood.

`PMechFlipGuard` is a distinct transition mode and owner from D1b `QuarantineAll`: it reuses only
D1b's two-family nft guard install/ACK/readback primitive and counter-read mechanics. It MUST NOT
invoke D1b's quarantine lifecycle rule that closes the old production permit and drains held frames
to DROP/uncertain immediately after guard ACK. Shadow's existing NFQUEUE epoch remains the
Go-owned ACCEPT baseline; flip mode fences only new Shadow submissions and drains already-held
frames with that baseline. The flip mode has its own generation/status witness, so a D1b
quarantine transition cannot be mistaken for a Shadow flip.
Every `PMechFlipGuard` base-chain/per-ifindex DROP increments a named owner counter
`xpf_ipsec_flip_guard_hits_<family>_<hook>_g<generation>_s<install_sequence>` exactly once per
packet; later DROP hooks do not increment. The fixed metric and transition-alarm reason is
`FLIP_GUARD` (E26); these nft hits do not emit a wire event. A user-space E26 failure, if emitted,
uses the existing `LEASE_EPOCH` byte through `DenyEventSink`.
`PMechFlipGuardWitness` is retained without an actor or permit and exports `guard_accumulated + live`
for both families. It retains a bounded metadata chain/rule with `{runID,generation,
primary_reason=FLIP_GUARD, reason_mask=0, install_sequence,label_schema}` and a
`PMechFlipCounterJournal`; after hook detach/quiesce ACK it
reads final counters (including the read→detach interval), fsyncs the rollup before counter/metadata
GC, and recovers idempotently after restart under the original `runID`. Counter userdata is never
used. A failed ACK/removal leaves the named objects and witness live; the cell cannot silently lose
an E26 terminal count.
For the §4.4 collector key, every flip-witness row projects
`primary_reason=FLIP_GUARD`, `reason_mask=0`, and `counter_sequence=install_sequence`; thus its
`{source,generation,primary_reason,reason_mask,counter_sequence}` identity is stable across restart
and cannot double-add a journaled final delta.


The flip is a guarded sequence, not a cross-subsystem atomic operation:
1. Install the higher-priority two-family P-MECH flip guard and wait for D1b ACK/readback.
2. Fence only new Shadow submissions (do not close the production NFQUEUE epoch) and drain every
   already-held Go frame with its baseline ACCEPT terminal, waiting for the Shadow drain witness;
   late shadow results/copies are discarded by the ShadowResultTombstone and cannot affect that
   terminal.
3. Stage the Enforcing actor/runtime with permit CLOSED and no OPEN authority.
4. Under the guard, replace and read back the matching nft generation/spec; a failure leaves guard +
   CLOSED permit and invokes the D1b deny-only recovery.
5. Publish the matching RuntimeView/protocol generation and verify actor status, fence, worker set,
   and witness equality while the permit remains CLOSED; no descriptor may enter the new phase yet.
6. With the permit still CLOSED, quiesce/final-read/fsync and remove the guard with D1b's per-family
   ACK/readback. If either family removal fails or is ambiguous, do not drain or replace anything.
   If partial removal leaves either family without a guard, install a fresh higher-priority two-family
   guard and await ACK/readback first; otherwise retain the remaining guard. Run D1b deny-only
   recovery with the permit CLOSED. Only an acknowledged removal of both family guards permits the
   final transition.
7. CAS/open the permit as the final transition. Only descriptors stamped with that new phase may
   enter. There is no claim that nft replacement and userspace publication were atomic.
During step 2, already-held Shadow descriptors finish under the Go baseline pass-through; they are
drained and never reinterpreted as enforcing.

On any unavailable evaluator, isolation violation, budget breach (duration, divergence, or cumulative
accepted count), stale generation, missing owner authorization, flood deferral expiry, or witness gap
before step 7, remain in Shadow pass-through or enter deny-only with the reason evidence; the permit is
never opened. The permit stays CLOSED throughout steps 3–6; if step 5 or step 6 fails, retain the remaining guard or,
if partial removal leaves a family unguarded, install a fresh two-family guard with ACK/readback
before any drain or replacement, then run deny-only recovery. After step 7 opens, any post-activation
failure first fences the active permit epoch and then installs a fresh higher-priority two-family
guard with ACK/readback before draining or replacing that epoch; it never claims to retain a guard
that was already removed. In all cases enter deny-only for a new generation, drain that phase, and
never reopen the old epoch. There is no live V-FLIP claim until this guarded, generation-scoped
witness is proven; otherwise P-MECH remains observational Shadow or deny-only, or is PLAN-KILLED.

---

## §6 Threat-model delta vs r6 S1 (+ G6 accounting)

G6 accounting (parent steer): r5 §1 framing ("deliberately open", "forward with no policy/…", `/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md:46-53`)
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
  (receive), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:147-161` (config sans evaluator), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:529-581` (submitEligible),
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:193-197` (Adjudicated = lease minted), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:381-394`
  (`allows` epochs-only), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/slowpath_reinject_9506.rs:801-874` (admit gates).
- Provenance + registry + Enqueue gate: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/origin.go:26-108`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:312-334`.
- Wiring (STN=BindInterface, if_id validation, live ifindex, 4-class keys): `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go:37-40,95-106,285-332`.
- Permit/census/VRF/outlet refusal: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_topology_owner_9506.go:184-243`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_reinject_supervisor.go:349-351` (Safe-gated OPEN), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_reinject_supervisor.go:142-146` (permitRecord).
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
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/forwarding/mod.rs:223-251` (pair fn, xfrmi/MAC-less note),
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:3065` (nonzero gate), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:2005-2009` (default_action), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/forwarding/unzoned_tunnel_host_inbound_9941_tests.rs:8-12`
  (zone-0 global admit), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:174-198` + #9989 (UNATTRIBUTED).
- Policy entries + actions: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:125-135` (Permit/Deny/Reject, default Deny), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:2819-2870`
  (entries), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:2915-2973` (ICMP/L3-aware), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/policy.rs:3390+` (junos-host).
- Worker order + NAT + install + host path: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs` lines cited inline in §3.1–§3.2
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:446`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:752-753`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1720-1789`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1862-1869`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:1953-1956`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2021-2064`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2625-2766`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2870-2874`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2962`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3207-3323`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3495-3504`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4089-4093`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4297-4300`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4335-4336`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4516-4518`).
- Hit authority + foreign verdict: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/session_hit_authority.rs:5-113,139-167,183-190,259-326`.
- Sessions + discriminator + install + sync: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/key.rs` (5-tuple + `TunnelDiscriminator` + `routing_domain`),
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/discriminator.rs:8-25,132-136` (#7188 d6), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/entry.rs:83-92` (#4983 stamp),
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/install.rs:100-104,142-150` (cap + refusal), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/README.md:1071-1168` (origins, caps, sync),
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/types/runtime.rs:542-613` (WorkerCommand), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/types/runtime.rs:571-572` (replication), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/worker_queue.rs:80,591-623` (bounds).
- Deny events/counters/metrics: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/event_emit.rs:138,230,333`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/host_inbound_policy.rs:170`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:176`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/event_stream/codec/decode.rs:50-52`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/api/metrics_ipsec_capture_10478.go:14-60`,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_pipeline_9506.go:53-65`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:171-198`.
- RPDB bands + FBF/PBR: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/routing/rules.go:64-90`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/routing/pbr_applied_7422.go:22-24`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/routing/fibimport.go:98-102`
  (usp0-resolves-in-main note), `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/routing/README.md` band table.
- Plans: G1 (`/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md:262-289`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md:1967-1969` C36-unbuilt); G2 (`/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md:1446-1463` item 8, r6 §6 `/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md:1734-1814`, §9.1 Q1
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md:1981-1983`, K2 `/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md:2039-2041`); G3 (`/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md:280-289`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md:1081-1088`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md:235-239`); G4 (`/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md:475-478`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md:645-651` N5,
  `/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md:684-686`); G5 (`/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md:735-768` §12.4, no §4.4 bullet); G6 (`/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md:46-53` struck; `/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md:41-89` §1.1; `/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md:147-274`
  §1.3–§1.4; delta `/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-delta.md` C04/C06/C17/C23/C46); r6 §3.1–§3.2 (`/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md:1050-1154`), §3.5 (`/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md:1368-1463`), §4 prohibitions
  (`/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md:1467-1502`), §8 retained (`/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md:1879-1975`), §9 (`/home/ps/git/pi-xpf/.claude/worktrees/9506-reground/docs/pr/9506-xfrm-capture/r6-plan.md:1977-2056`); r5 §4.3–§4.4 (`/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md:238-289`), §6 (`/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md:401-493`),
  §12 (`/home/ps/git/pi-xpf/.claude/worktrees/9506-xfrm-capture/docs/pr/9506-xfrm-capture/plan.md:641-825`).

---
## §B Design-input review steers (adopted; grounded above, not taken on authority)

1. Worker-pipeline adjudication (not socket-thread mirrored evaluation): adopted as D6/D13 — grounded in
   r5 §4.3–§4.4 + `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:3-15` + #7167/#7176.
2. Dedicated per-worker data queues + pool slots + poll budget; `WorkerCommand` control-only: adopted as
   D11–D12 — grounded in r5 §4.3 + `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/worker_queue.rs` bounds + `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/types/runtime.rs:542-613`.
3. Tunnel discriminator plus the NEW cross-discriminator alias index (no aliasing): adopted as D21 —
   grounded in `SessionKey` (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/key.rs:42-81`),
   the existing 1:N reverse index (`/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/mod.rs:29-39,1100-1106`),
   and `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/session_hit_authority.rs:5-7` + #7188/#6928 + r5 §2 multi-tunnel isolation. The new seam is specified in §3.5, not claimed as existing code.

### §B.1 r2 hostile-review disposition table

| Consolidated group | Reviewer IDs | r2 disposition and evidence |
|---|---|---|
| ZONE-JOIN | PlanRevA-A-P1, PlanRevB-B-P1 | **FIXED.** Rebuttal (A-P1): r2 removes raw `if_id`-only claiming. D1 joins same `if_id` only after `config.BindInterfaceOwnsRef` and marks duplicate/quarantined claims ambiguous; the ownership rule is grounded in `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/config/xfrmi.go:227-285` and staging in `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go:285-332`. |
| LIVE-IFINDEX | PlanRevB-P1 | **FIXED / KILL-GATED.** Rebuttal: D1c makes the live-ifindex table immutable per capture generation, refuses delete/recreate/name reuse via generation mismatch, and tests T12; D1d separately refuses to claim pre-census safety and K-P11 requires a continuously present future-master fence plus measured post-detection ACK. |
| FRAGMENTS | PlanRevA-A-P1 | **FIXED-SCOPE-CUT / KILL-GATED.** Rebuttal (A-P1): V1 refuses validated fragments before `FragPool` admission and never permits a fragmented datagram, so no partial emission or multi-original terminal protocol exists to get wrong. The design reuses `ClassifyCapturePayload`, `FragmentKey`, and `FragmentPiece`; malformed/uncertain pre-frame classification is counted and denied through the bounded `DenyEventSink`. A future fragment-permit contract is explicitly out of scope and would require the atomic batch/tombstone/canonical-L3 machinery before scope expansion. |
| REVERSE | PlanRevA-A-P1, PlanRevB-B-P1 | **FIXED.** Rebuttal (A-P1/B-P1): r2 names a NEW cross-discriminator alias index with atomic construction, eviction/generation/scope checks, native `None` collision counting, bounded multiplicity, and T22 cases; it no longer claims existing reverse machinery solves this. Existing 1:N index evidence is `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/mod.rs:29-39,1100-1106`; discriminator source is `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/session/key.rs:42-81`. |
| M3 | PlanRevA-A-P1, PlanRevB-B-P2 | **FIXED.** Rebuttal (A-P1/B-P2): r2 reconciles D21 with M3: snapshot-pinned prefix source, no-NAT overlap refusal, narrowly proven SNAT carve-out, commit revalidation, and E9 post-SNAT ambiguity. The four must-proves and kill polarity are explicit at §1.5/D5c. |
| WORKER | PlanRevA-A-P1, PlanRevB-B-P1 | **FIXED-CONTRACT / KILL-GATED.** Rebuttal (A-P1/B-P1): r2 adds worker-set generation, bounded queue/flow/slab caps, dead-worker orphan reaper, `ProvisionalJournal` CAS recovery for verdict-issued handles, and priced `Vec` allocation rather than a false no-allocation claim. Anchors: `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/logical_ingress.rs:79-85`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/worker_queue.rs:37-80`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1-120`; K-P10 kills blind rollback/leak. |
| SHADOW | PlanRevA-A-P1 | **FIXED-CONTRACT / KILL-GATED.** Rebuttal (A-P1): r2 gives an explicit `consumeFrames` call site and a separate bounded `ShadowFrame`/`EvaluationMode::Shadow` transport with no production session/NAT/flow-cache/HA/counter side effects. The call site is `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:383-428`; K-P9 forces unavailable/disable or PLAN-KILL if isolation is not proven. |
| DENY | PlanRevA-A-P2 (three findings) | **FIXED.** Rebuttal (A-P2): r2 replaces strings with a `u8` reason contract, allocates the legacy 5/6 values plus closed 32–60 range, maps Rust and Go terminals, and adds bounded `DenyEventSink` plus alarm/counter loss handling. The wire evidence is `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/event_stream/codec/rt_flow.rs:100-104`, `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/event_emit.rs:12,138,279`; E1–E37 now include poison, ECN/parse, HA, ALG/policer, rollback, shutdown/handoff, submit-gate, pre-worker fragment refusal/classification error, evaluator unavailable, and policy-unavailable terminals. |
| STAGES | PlanRevA-A-P2 | **FIXED-CONTRACT.** Rebuttal (A-P2): r2 corrects “screen first” to “first security stage after parse/decap,” requires discriminator/generation/policy-hash flow-cache validation, makes the P-MECH DNS fastpath SKIP for both hooks (INPUT misses E37), and suppresses challenge/reply TX. Actual worker anchors are `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/poll_descriptor/mod.rs:446,628-641,1720-1738,2522,3296-3309,4150,4171,5799`. |
| INPUT | PlanRevA-A-P2 | **FIXED.** Rebuttal (A-P2): r2 defines sink-skipping terminalization after supervisor NF_ACCEPT, exact zero-byte exemption only for `CompletionInputReady`, per-frame terminal identity, timeout uncertainty, and unlock-before-committer (`p.mu` never spans lease/sink). Supervisor authority is `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_reinject_supervisor.go:602-656`; resolver state is `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/nfqueue/pipeline.go:707-746,848-904`. |
| STAGING | PlanRevB-B-P2 | **FROZEN-HISTORICAL (r2; superseded by current D1b).** Rebuttal (B-P2): r2 recorded first-invalid fail-all → per-tunnel skip-mark-continue, alarm/counter, and empty-generation refusal. Existing all-or-nothing behavior is `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/daemon/ipsec_capture_wiring_9506.go:285-332`; current D1b additionally requires five-reason masks, two-family guard ACK, and no-actor witness recovery. |
| UPGRADE | PlanRevB-B-P2 | **FIXED.** Rebuttal (B-P2): r3 §5.6 adds mandatory Go/Rust lockstep codecs, protocol-floor/tunnel-row anchors, standby-first upgrade, old-descriptor drain, symmetric deny-only rollback, and status `FailoverRefused`/`PMechAdmission=DENY_ONLY` without peer floors/tags (r5 completes the rename in §5.2 and here). |
| SLICE | PlanRevA-A-P2 | **FIXED.** Rebuttal (A-P2): r2 names the actual worker poll file, the alias-index files, the deny bridge, the no-permits-before-S9.5 proof invariant, and corrected pre-worker fragment-refusal cells; no wildcard-only owner remains. Slice files/order are §5.2–§5.4 and actual worker loop `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/afxdp/worker/loop_body/mod.rs`. |
| CITES | PlanRevA-A-P3 | **FIXED/REBUTTED.** Rebuttal (A-P3): drifted r1 claims are corrected in r2's D1, D11, D21, D22, §3.2, §4.1, §5.2, and §A anchors; every changed code claim names the master worktree and line range. The source/base statement is at `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/docs/pr/9506-xfrm-capture/pmech-design.md:7-13` and §A. |
| D12a | PlanRevA-A-P2, PlanRevB-B-P2 | **FIXED/DECIDED.** Rebuttal (A-P2/B-P2): Option A is explicitly authorized only for stateless ICMP/ICMPv6/flowless shapes, with two proof cells; Option B is deferred; stateful INPUT remains E37. The exact boundary is D12a and the proof/kill gates are §5.3–§5.5. |

### §B.2 r3 hostile-review closure matrix (25 findings → 21 consolidated items)

| # | Consolidated finding | r3 disposition | Closed contract |
|---:|---|---|---|
| 1 | D1 ownership predicate | **FIXED.** Export `BindInterfaceOwnsRef`; config remains the single ownership authority. | §1.1/D1–D3; §5.2 |
| 2 | M3 selector/route inventory | **FIXED / KILL-GATED.** S9.1 derives rendered effective selectors (including valid legacy `RemoteID`/`LocalID` fallback provenance), intersects them with complete main-table-254 forwarding routes across all protocols and every ECMP nexthop, and refuses implicit/missing selectors, partial/unresolved routes, stale generations, and overlap. | §1.5/D5c; E21/E22 |
| 3 | Bounded deny/alarm owner | **FIXED.** One bounded `DenyEventSink` emits tuple-rich deny events and rate-limited `PMechAlarm`; sink loss is counted and never changes DROP. | §4.1–§4.2 |
| 4 | Metric cardinality and cause split | **FIXED.** Closed reason labels only; no raw tunnel labels; session, alias, ALG, filter, policer, fragment, bypass, quarantine, and decode causes are separate. | §4.3–§4.4 |
| 5 | Proof-cell completeness | **FIXED / KILL-GATED.** Fault-injection cells cover E1–E37; staging, tombstone, RuntimeView, quarantine, and fence cells are explicit; live cells are representative and hook-reachable. | §5.4–§5.5 |
| 6 | VRF-master bypass exposure | **FIXED / PLAN-KILL IF UNPROVEN.** Preemptive future-master fence is required; census timing is not treated as safety; post-detection ACK is measured. | §1.1/D1d; K-P11 |
| 7 | Live-ifindex/name reuse | **FIXED.** Immutable per-generation table plus named `T12_delete_recreate_name_reuse` and `T12_tolerant_load_parity` cells prove mismatch refusal and tolerant-load parity. | §1.1/D1c; §5.4 |
| 8 | D12a proof identity and dangling references | **FIXED.** D12a-C1 and D12a-C2 are the sole stable proof labels; stateful INPUT remains E37. | §1.6; §3.2; §5.4–§5.5 |
| 9 | Missing tunnel-row wire admission | **FIXED.** Missing/unknown rows are E33 `ADMIT_TUNNEL_ROW_MISSING`, never a generation default. | §2.5/D15; E33 |
| 10 | Worker stage order and fastpaths | **FIXED.** Parse→screen→decision-only flow-cache→session→ACK check→DNAT/NAT→route→route-eligible strict-SYN→policy→SNAT→install; DNS/challenge TX paths are suppressed or skipped. | §3.1–§3.2/D17 |
| 11 | NoRoute/HAInactive/punt guards | **FIXED.** NoRoute, non-local INPUT, HAInactive, redirect, and punt-seed paths are explicit DROP guards with no alternate outlet. | §3.2; E19/E20/E34 |
| 12 | Session lookup observability | **FIXED.** Lookup/poison/unavailable has distinct `ipsec_inner_session_lookup_errors_total` and `ipsec_inner_session_lookup_recoveries_total`; the affected frame still drops while table recovery is counted. | §4.3; E8 |
| 13 | Reason decoder ownership | **FIXED.** `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/logging/ringbuf.go` owns pre-admission closed-reason decoding/severity mappings and lockstep tests; an unknown event-decoder byte is `ipsec_inner_event_decode_errors_total` + `VERSION_SKEW` alarm while its packet remains terminal, whereas an unknown pre-admission reason is E33/refusal/DROP. | §4.1; §5.2; E33 |
| 14 | Partial staging and quarantine semantics | **FIXED / AVAILABILITY COST EXPLICIT.** Per-tunnel skip continues only to build metadata, then any skip installs node-wide `QuarantineAll` with a five-value reason mask, deny-first two-family guard ACK/readback, per-ifindex/zero-admitted nft DROP rules, old-epoch drain, persistent counter rollup, and no-actor recovery witness; no old authority is reused. | §1.1/D1b; E3/E27/E2/E21 |
| 15 | RuntimeView refresh interleaving | **FIXED.** The poll tick's one immutable view binding is reused with zero new `load()` calls in the P-MECH entry (canary-guarded); every stage binds `view_generation`, and refresh interleaving refuses. | §2.4/D13; §5.2; §5.4 |
| 16 | Upgrade, downgrade, and failover | **FIXED / DENY-ONLY FALLBACK.** Go/Rust lockstep targets protocol 29 with `MinProtocolPMech=29`, standby-first drain, explicit Rust→Go downgrade restore order, and `PMechFailoverVerifier`/status `FailoverRefused` before OPEN; missing peer floors/tags/equality stays fenced deny-only. | §5.2; §5.6 |
| 17 | Shadow flip semantics | **FIXED / KILL-GATED.** Shadow is observational Go-owned ACCEPT pass-through with read-only observed permit epoch, no production side effects, bounded signed budget/max duration, flood-deferral guard, and a non-atomic two-family guard→CLOSED permit→nft readback→RuntimeView publish→guard removal→final OPEN sequence; pre-open failures keep CLOSED and restore a guard, while post-activation failures install/ACK a fresh guard before drain/replacement. | §2.3/D10; §2.6; §5.7 |
| 18 | M3 self-reference | **FIXED.** The design now points to §1.5/D5c rather than mutable document line numbers. | §1.5/D5c; §B.1 |
| 19 | Fragment late/duplicate handling | **FIXED-SCOPE-CUT.** V1 denies all fragments with bounded generation tombstones; late/name-reuse and duplicate cells exist; no `FragPool` reassembly claim. | §3.6/D22; E30; §5.4 |
| 20 | Protocol-floor implementation ownership | **FIXED.** Go `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/pkg/dataplane/userspace/protocol.go` and Rust `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/protocol/control.rs` + `/home/ps/git/pi-xpf/.claude/worktrees/9506-mechdesign/userspace-dp/src/protocol/snapshot.rs` are mandatory, not conditional; floors anchor at the tunnel-row definitions. | §5.2; §5.6; E33 |
| 21 | Alias replication failure | **FIXED.** Replication failure is an E10 terminal with `ipsec_inner_alias_replication_failures_total`; it is not folded into ambiguity or generic rollback. | §3.5/D21; §4.3; E10 |

### §B.3 r5 hostile-review closure matrix (7 findings → 11 consolidated items)

| # | Consolidated finding | r5 disposition | Closed contract |
|---:|---|---|---|
| 1 | Zero-new-load view reuse | **FIXED.** Normative D13, §B.2 row 15, and the §5.4 D22 cell now state reuse-the-tick-binding with zero new `load()` calls in the new entry; the tick's one `ArcSwap` load and reader-load canary are the grounding. | §2.4/D13; §5.2; §5.4; §B.2-15 |
| 2 | Journal reason identity | **FIXED.** The fsynced journal record persists `primary_reason` + `reason_mask`; a dedicated restart-after-counter+metadata-GC cell recovers the witness series and dedup key from the journal alone. | §1.1/D1b; §4.4; §5.4 |
| 3 | M3 per-frame ingress membership | **FIXED.** The worker requires per-frame membership in the frozen per-tunnel ingress prefix set plus commit revalidation against the same snapshot; the 0/0-with-disjoint-routes hole is closed and violations are E21. | §1.5/D5c; E21; §5.4 |
| 4 | Shared S4 OPEN predicate | **FIXED.** `tryOpenIpsecPermitAfterFenceAck`/`tryOpenPermit` is the sole opener with SAFE/fence AND NOT `FailoverRefused` AND generation-bound flip approval; the host-fence reconciler is listed in §5.2 and a race cell covers refusal/incomplete-flip. | §1.2; §5.2; §5.4; §5.6 |
| 5 | Header kill pointer | **FIXED.** The header authorizes D12a Option A with (§2.5/D12a, §5.4–§5.5), matching every other conditional pointer. | header; §5.5 |
| 6 | `FailoverRefused` rename | **FIXED.** The §5.2 topology-owner bullet and §B.1 UPGRADE row now name status `FailoverRefused`/`PMechAdmission=DENY_ONLY`, matching the §5.6 contract. | §5.2; §5.6; §B.1 |
| 7 | `TerminalAttemptYes` scope | **FIXED.** The reservation is scoped to uncertain outcomes; the supervisor-refusal `{Dropped, Yes, nil}` is the sole definitive `Yes`. | §2.5/D12; E29/E35 |
| 8 | Shadow budget/signer/cap values | **OWNER-DEFERRAL WITH RATIONALE.** Fields, cumulative `max_accepted`, pinned-anchor signer policy, expiry/cap enforcement, and K-P12 polarity are specified; numeric values are owner-supplied at install sign-off. | §5.7; K-P12 |
| 9 | `alarm_cooldown` value | **FIXED (INSTANTIATED).** `PMECH_ALARM_COOLDOWN=60s` per transition key, owned by the pipeline consumer; G5 may tune only with a finite bound and reviewer approval. | §4.1; §5.2 |
| 10 | E29/E35 definitive-vs-uncertain split | **FIXED.** Only a pre-committer invalid outcome with explicit `TerminalAttemptNo` may use retained-handle DROP and is definitive E29; every post-committer pre-syscall validation error is E35 uncertain/no retry, and ANY post-entry syscall error is E35 with `TerminalAttemptYes`. The §5.4 committer cell proves each branch. | §2.5; E29/E35; §5.4 |
| 11 | §4.3 counter owner split | **FIXED.** Worker-detected causes increment in Rust; pre-dispatch/completion/decode causes increment in Go; Go exports aggregated Rust stats without duplicate increments. | §4.3–§4.4 |

*(End of P-MECH mechanism design. G1/G2/G4 mechanisms are specified; G3 INPUT is authorized only for
the proof-backed stateless Option A subset, while stateful INPUT remains E37 until Option B is proven.
G5 implementation/live proof, M1–M4, and the two D12a proof cells remain kill-gated. G6 is accounted
in §6; §9.1 Q1 is answered in §1.4–§1.6. This is a conditional design record, not implementation
authorization.)*
