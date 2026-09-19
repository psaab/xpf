# #9506 r6 targeted re-plan — post-#10302 fence world (PLAN ONLY)

## 0. Status, scope, inputs

**PLAN r6** — design docs ONLY, no production code, no PR to master.
Targeted re-plan per the r6 delta memo recommendation, not a rewrite, not a kill.
Parent reviews this plan, runs hostile plan-review, then authorizes implementation slices.

- Branch: `research/9506-reground`, HEAD at plan-write time `c4f664191`
  (`docs: reground 9506 r5 plan on current master (r6 delta)`), reground base
  `c26bf5e7e` (master at reground time). r5 base `7ef226474`.
- Inputs (read fully): r5 plan at
  `research/9506-xfrm-capture:docs/pr/9506-xfrm-capture/plan.md` (825 lines,
  S0 adjudication disposition), r6 delta memo at
  `docs/pr/9506-xfrm-capture/r6-delta.md` (58 claims checked: 41 CONFIRMED,
  11 FALSIFIED, 6 STALE-UNCERTAIN; top-5 load-bearing deltas; S12.5 validity).
- Re-planned in this file (self-contained, cites current master `file:line` on
  every mechanism claim): S1 threat model, S4.2 divert+fence layering, S4.5
  re-entry DECISION, S4.7 prohibitions, S8 G2/T12 fence-aware gates, S12.5
  items 5–6 re-sign drafts, advisory wording fix for
  `pkg/config/compiler_ipsec_plaintext_warn.go:102-104`.
- Retained by reference (NOT re-specified; r5 text stands except where struck
  in §12): commit table + terminal accounting (now code-backed), NFQUEUE
  transport choice (prototype-backed), shadow phasing, T22 shape (re-baselined
  on M1/M2), fragment contract (with #9950 intersection duty), S12.3 mechanism
  clauses, S12.5 items 1–4/7. See §8.
- Gate: hostile re-review of the re-planned sections + the 2 re-signs. No S1+
  slice may cite a sentence struck in r5 §12 or in r6 §1/§4.
- Kill polarity preserved: owner refuses re-sign, or the S3 fence+divert
  coexistence spike proves unworkable, kills the plan. §9 records the
  disposition. A KILL with proof is a valid deliverable; hand-waving is not.

Citation convention: `pkg/...:line` and `userspace-dp/src/...:line` are
reground-worktree paths at `c4f664191` unless noted. Every mechanism sentence
in §1–§7 carries at least one such citation. Proposal sentences (new table
names, priorities, rule text) are marked `PROPOSAL` and need no citation, but
their coexistence proof cites the fence/divert/queue code it orders against.

---

## 1. S1 threat model rewritten for the post-#10302 world

### 1.1 Struck r5 sentences (do not cite)

The following r5 §1/§4.7 claims are FALSIFIED by #10302 and are struck for r6
(delta C04/C06/C17/C23/C46):

- ~~"The armed forward path is deliberately open (`daemon_transit_gate.go`
  removes the barrier when armed)."~~ Falsified:
  `pkg/daemon/daemon_transit_gate.go:51-56` (forward hook remains policy-DROP
  while armed), `pkg/daemon/daemon_transit_gate.go:385-389`
  (`applyTransitBarrier` never removes the fence while opening),
  `pkg/nftables/transit_barrier.go:143-149` (armed fence retains DROP policy).
- ~~"Admission is warning-only. An authenticated peer's inner packets forward
  with no policy/session/NAT/screen/counter/deny."~~ Inverted for FORWARD
  transit: `pkg/daemon/daemon_transit_gate.go:122-124` (xfrmi absent from the
  allowlist, remains dropped), `pkg/nftables/transit_barrier.go:100-110`
  (every other packet reaches DROP policy; xfrmi plaintext remains dropped).
  Warning-only admission itself still holds
  (`pkg/config/compiler_ipsec_plaintext_warn.go:120-186` never rejects;
  `pkg/config/README.md:1371-1374`), but the consequence is no longer
  open forwarding.
- ~~"#7191/#5275 unarmed-only barrier; load-bearing bypass."~~ The bypass half
  (armed-open) is closed; unarmed-only must be struck. Gate+barrier present
  AND extended by the armed fence #10302 (delta C17).
- ~~"Refuted object = unconditional policy-DROP chain; divert carries no
  verdict, drops nothing by rule" as a claim that no such chain exists.~~
  Master HAS unconditional DROP (unarmed #7191) + policy-DROP fence (armed
  #10302); the fence IS a policy-DROP chain (delta C23). The second half
  (divert carries no verdict) is retained and re-proved in §2.
- ~~"No unconditional armed DROP chain (only the pinned divert rule set)"
  (r5 §4.7).~~ Struck in §4.

What still holds from r5 §1 (CONFIRMED, retained): route-based `bind-interface
stN` is the ONLY IPsec model xpf supports, policy-based hard-rejected
(`pkg/config/compiler_ipsec_plaintext_warn.go:20-22`,
`pkg/config/compiler_prewalk.go:367-369`, delta C01); kernel XFRM decrypts and
plaintext surfaces on the xfrmi
(`pkg/dataplane/userspace/ingress_exclusions.go:182-184`,
`userspace-dp/src/server/README.md:254-256`, delta C02); xfrmi excluded from
AF_XDP adjudication in BOTH planes via the SecureTunnel class and
`include_userspace_binding_interface`
(`pkg/dataplane/userspace/ingress_exclusions.go:141`,
`pkg/dataplane/userspace/ingress_exclusions.go:381-382`,
`userspace-dp/src/server/helpers/planning.rs:433-448`,
`userspace-dp/src/server/helpers/planning.rs:345-348`, delta C03 with the
ownership-or-device-kind drift note at
`pkg/dataplane/userspace/ingress_exclusions.go:150-158`).

### 1.2 Current steady state (fail-closed-drop)

While armed, kernel transit is closed by TWO independent legs, either of which
closes routed transit alone:

1. Sysctl leg: `ip_forward=0/1` pair at
   `pkg/daemon/daemon_transit_gate.go:188-197` (`transitForwardSysctlPaths`),
   written by the sole **daemon** writer `writeTransitForwardSysctls`
   (`pkg/daemon/daemon_transit_gate.go:218-233`), driven from the single ready
   predicate (`dataplaneArmed && AttachedXDPLinkCount > 0`) under `transitGateMu`
   (`pkg/daemon/transit_gate_tick_9725.go:56-89`,
   `pkg/daemon/transit_gate_tick_9725.go:91-104`,
   `pkg/daemon/daemon_transit_gate.go:246-254`). A separate
   close-only cleanup process writes both knobs after daemon exit and verifies
   barrier-first/read-back (`pkg/daemon/transit_cleanup_9725.go:23-24`); it
   cannot open transit or compete with the ready predicate. Opening installs
   the fence BEFORE raising the knobs; closing installs the unconditional
   barrier BEFORE writing zero
   (`pkg/daemon/daemon_transit_gate.go:352-383`,
   `pkg/daemon/transit_gate_tick_9725.go:63-89`).
2. nftables leg: table `xpf_transit_barrier` in BOTH inet and bridge families
   (`pkg/nftables/transit_barrier.go:11-13`,
   `pkg/nftables/transit_barrier.go:124-129`), base chain `forward`, hook
   forward, filter priority, policy DROP
   (`pkg/nftables/transit_barrier.go:164-175`), installed via
   `InstallTransitBarrier` (unarmed, empty spec, unconditional DROP) and
   `InstallArmedTransitFence` (armed, pinholes + DROP policy)
   (`pkg/nftables/transit_barrier.go:139-149`,
   `pkg/nftables/transit_barrier.go:197-225`). The bridge leg matters because
   `ip_forward` does not govern bridged frames and the repo creates bridge
   domains (`pkg/daemon/daemon_transit_gate.go:56-57`,
   `pkg/nftables/transit_barrier.go:112-116`). Flowtable leg is a deliberate
   NO-OP pinned by test (`pkg/daemon/daemon_transit_gate.go:59-62`,
   `pkg/nftables/transit_barrier.go:118-122`).

Armed pinholes (the ONLY ingress ACCEPTs while armed) are resolved by
`armedTransitFenceSpec`
(`pkg/daemon/daemon_transit_gate.go:107-124`): tracked runtime XDP links whose
kernel names still resolve (unmarked `iifname` ACCEPT), plus the daemon-owned
`xpf-usp1` TUN ONLY through an exact interface+mark conjunction
(`pkg/daemon/daemon_transit_gate.go:159-168`,
`pkg/nftables/transit_barrier.go:177-195`). `xpf-usp0` is LocalDelivery/gated-only
and is NOT a FORWARD pinhole
(`pkg/daemon/daemon_transit_gate.go:116-117`,
`pkg/nftables/transit_barrier.go:107-110`). Direct route-based IPsec plaintext
arrives on its daemon-owned xfrmi and remains absent from the allowlist
(`pkg/daemon/daemon_transit_gate.go:122-124`); kernel-XFRM reinjection instead
arrives through the marked `xpf-usp1` queue. A failed fence install keeps
transit closed (`pkg/daemon/daemon_transit_gate.go:390-411`,
`pkg/daemon/transit_gate_tick_9725.go:64-78`); removal failure is surfaced, not
hidden (`pkg/nftables/transit_barrier.go:227-239`). Pins:
`pkg/daemon/transit_fence_10302_test.go:54-68` (unmarked = only tracked XDP,
marked = one `xpf-usp1` conjunction; leave-alone/unmanaged/xfrm1/xpf-usp0 never
in the unmarked set),
`pkg/nftables/transit_barrier_9852_test.go:102-193` (plan shape, mark bytes LE
golden for `0x58465001`).

### 1.3 Residuals (what the fence does NOT close)

Threat moved fail-open-forward → fail-closed-drop + three narrow residuals.
Each is a CURRENT gap with a distinct owner and test surface:

**(a) INPUT/host-bound decrypted ingress (open, unadjudicated, including a
VRF-master bypass).** The fence covers hook `forward` ONLY
(`pkg/nftables/transit_barrier.go:164-175` sets `ChainHookForward`; no input
chain exists in `xpf_transit_barrier`). Decrypted ingress destined to a
firewall-local address (IKE-adjacent control, tunneled management, host
services) traverses hook `input`, never meets the fence, and is judged only by
the host-inbound/lo0/gap chains (`inet xpf_hostinbound` prio 10,
`inet xpf_hostinbound_gap` prio 11, `inet xpf_lo0` prio 0;
`pkg/nftables/netlink_installer.go:25-34`). Those chains judge by destination
zone/service, not by tunnel zone policy, and no IPsec-entry adjudication runs
before them (no IPsec owned-frame entry exists; the pattern exists at
`userspace-dp/src/afxdp/logical_ingress.rs:79` used by
`userspace-dp/src/afxdp/wg/decap.rs:214` and
`userspace-dp/src/afxdp/gre.rs:923`, delta C36).

The input twin's `iifname == stN` match has a sharper VRF failure mode:
route-instance member resolution and the daemon's late bind can enslave an
xfrmi to an l3mdev VRF master
(`pkg/daemon/daemon_run_routehelpers.go:712-745`,
`pkg/daemon/daemon_apply_interfaces.go:330-344`). At `LOCAL_IN`, the l3mdev
receive handler substitutes the VRF master for `skb->dev`, so the `stN`
predicate receives zero hits while the master receives the packet
(`pkg/config/junos_host_deny.go:880-890`,
`pkg/dataplane/userspace/junos_host_vrf_scope_6619_test.go:16-21`). r6
therefore chooses **explicit pre-admission VRF refusal**, not a guessed
master-name capture rule: S3 rejects every admitted xfrmi whose master is a
VRF/l3mdev, and the pre-open census repeats that rejection. A rejected master
gets a safe host-input fence in the canonical host-inbound view: an explicit
default-deny/master row precedes service accepts, no `stN` or service ACCEPT is
rendered for the rejected tunnel, and a master carrying unrelated accepted
services causes the configuration itself to be rejected rather than
overmatching those services. A runtime VRF-master observation immediately revokes the permit
epoch (`OPEN→CLOSING`, idempotently), keeps input listeners DROP-only, and
reports tunnel-DOWN only after both host-fence and conntrack ACKs; it never
claims an input receipt or policy decision for the enslaved xfrmi.

The owner MUST resolve whether concrete `D_usp1` is the **main-table,
non-policy-routed** identity and whether it is itself an l3mdev VRF. If any
admitted stN is enslaved to that master, if the outlet is enslaved, or if the
singleton selects another table, the `D_usp1` q0 scope is refused and this plan
cannot claim re-entry; the owner must either provide a separately reviewed
VRF-aware input/re-entry/provenance mechanism or choose a main-table,
non-VRF concrete outlet domain. This removes the silent host-inbound
fall-through while preserving host-bound permit/deny parity and the
mutated-host-bound DROP rule (r5 §6.10/H6).
The #9646 local-address lifecycle remains relevant only to the existing
userspace maps
(`pkg/dataplane/userspace/maps_sync.go:302-306,967-972,1077-1086`,
`pkg/dataplane/userspace/local_address_capacity_9646.go:47-52`), not to
9506's input capture predicate.

**(b) Marked-`xpf-usp1` semantics (shipped adjudicated path + deliberate
residual).** `xpf-usp1` is a multi-queue TUN; queue zero is the sole
adjudicated writer, queue one is delegated
(`userspace-dp/src/slowpath.rs:31-38`, `userspace-dp/src/slowpath.rs:110-118`).
`enqueue_adjudicated` tags `PacketQueue::Adjudicated` on the shared
`tx_delegated` outlet (`userspace-dp/src/slowpath.rs:974-985`);
`enqueue_delegated` tags `PacketQueue::Delegated` on the SAME outlet
(`userspace-dp/src/slowpath.rs:987-998`). A TC ingress clsact classifier
(`install_queue_mark_classifier`, `load_queue_mark_program`,
`userspace-dp/src/slowpath.rs:168-318`) clears skb mark for every queue, then
sets `0x58465001` (`ADJUDICATED_TRANSIT_MARK`,
`userspace-dp/src/slowpath.rs:36-37`, mirrored by
`pkg/nftables/transit_barrier.go:23-28`) IFF `skb->queue_mapping == 1`
(queue_index 0 + 1). Unknown queues remain explicitly unmarked and hit the
fence DROP policy (`userspace-dp/src/slowpath.rs:168-173`). The fence admits
`xpf-usp1` ONLY with the exact mark conjunction
(`pkg/nftables/transit_barrier.go:181-194`,
`pkg/daemon/daemon_transit_gate.go:164-168`); the kernel holds NO accept for
unmarked `xpf-usp1` (`pkg/nftables/host_inbound_reinject_9637.go:19-29`).
Residual: both adjudicated xfrm reinjects AND delegated traffic arrive with the
same iifname; the queue-index classifier marks only the adjudicated queue, and
the fence always requires the conjunction
(`pkg/daemon/daemon_transit_gate.go:113-117`,
`pkg/daemon/README.md:2196-2201`). Semantics the r6 re-entry choice MUST
preserve: provenance is STRUCTURAL (queue identity → TC → mark), callers cannot
choose the queue through the delegated API
(`userspace-dp/src/slowpath.rs:974-977`), and a mark is never admitted without
its owning interface (`pkg/nftables/transit_barrier.go:15-21`). Any 9506
re-entry that writes q0 must join this single-writer discipline, not bypass it
(§3).

**(c) Fail-closed-but-unadjudicated DROP (closed, unaudited).**
Steady-state xfrmi FORWARD transit is now fence-dropped WITHOUT policy
evaluation: no zone rule, no session, no NAT, no screen, no permit/deny
counter distinguishes "policy-denied" from "fence-dropped-because-never-
adjudicated." The drop is fail-closed (safe direction) but carries no
adjudication evidence, no per-tunnel/per-rule attribution, and no divergence
telemetry. This is the gap #9506 still owns on the FORWARD half: converting
unadjudicated-DROP into adjudicated-DROP-or-permit with evidence, without
reopening the closed gate. The r5 commit table, supervisor deadline, and
uncertain-terminal accounting are retained for exactly this conversion (§8);
the S4.2 divert is the capture half, the S4.5 marked-queue re-entry is the
permit half, and fence-DROP remains the default for everything not explicitly
adjudicated-permitted.

### 1.4 CURRENT gap statement (replaces r5 §1 paragraph 1)

> Route-based IPsec (`bind-interface stN`, the only model xpf supports,
> `pkg/config/compiler_ipsec_plaintext_warn.go:20-22`) decrypts in kernel XFRM;
> plaintext surfaces on the xfrmi, excluded from AF_XDP adjudication in both
> planes (`pkg/dataplane/userspace/ingress_exclusions.go:141`,
> `pkg/dataplane/userspace/ingress_exclusions.go:381-382`,
> `userspace-dp/src/server/helpers/planning.rs:433-448`). While armed, FORWARD
> transit through the xfrmi is fence-DROPPED (policy-DROP + XDP/mark pinholes,
> xfrmi absent: `pkg/nftables/transit_barrier.go:100-110`,
> `pkg/daemon/daemon_transit_gate.go:122-124`) — fail-closed, but WITHOUT zone
> policy, session, NAT, screen, or adjudication evidence. INPUT/host-bound
> decrypted ingress bypasses the forward-only fence entirely and reaches the
> local input path without tunnel-zone adjudication. The ONLY adjudicated transit
> path is the structural `xpf-usp1` queue-zero → TC-mark → fence-conjunction path
> (`userspace-dp/src/slowpath.rs:974-985`,
> `userspace-dp/src/slowpath.rs:168-173`,
> `pkg/nftables/transit_barrier.go:181-194`), which no IPsec capture feeds
> today. #9506 converts unadjudicated-DROP into adjudicated verdicts with
> evidence on both hooks, but the INPUT twin's **V1 (r6 input-only scope)**
> promise is limited to admitted **non-VRF-enslaved** xfrmis; a
> post-detection, ACKed VRF-master census/refusal plus host-input fence closes
> the l3mdev substitution bypass. The bridge INPUT chain remains quarantine-only
> and the inet/bridge FORWARD paths retain their slave-visible ownership proof.
> Until then the gap is:
> **tunneled FORWARD traffic is unavailable (dropped without verdict) and
> tunneled INPUT traffic reaches the local input path without verdict.**

---

## 2. S4.2 divert+fence layering (filter priority/table/chain; ordering proof)

### 2.1 Fence facts the divert orders against (all cited, none re-derived)

| Fact | Citation |
|---|---|
| Table `xpf_transit_barrier` on inet AND bridge | `pkg/nftables/transit_barrier.go:11-13`, `:124-129` |
| Base chain `forward`, hook forward, type filter, priority filter (0), policy DROP | `pkg/nftables/transit_barrier.go:164-175`; prio constant `*nftables.ChainPriorityFilter` (`:165`); test pins hook+shape at `pkg/nftables/transit_barrier_9852_test.go:102-136` |
| Armed pinholes: unmarked `iifname ∈ {tracked XDP}` ACCEPT + marked `(xpf-usp1, 0x58465001/0xffffffff)` ACCEPT; everything else → DROP policy | `pkg/nftables/transit_barrier.go:177-195`, `pkg/daemon/daemon_transit_gate.go:107-124`, `:133-184` |
| xfrmi never in the allowlist; xpf-usp0 never a FORWARD pinhole | `pkg/daemon/daemon_transit_gate.go:116-124`, `pkg/nftables/transit_barrier.go:107-110` |
| Priority ordering is the determinism invariant (lower evaluates first; lo0 0 < host-inbound 10 < gap 11) | `pkg/nftables/netlink_installer.go:25-34` |
| Fence install is per-family independent; bridge-unsupported is a documented degraded-success sentinel | `pkg/nftables/transit_barrier.go:151-162`, `:39-43`, `:61-92`; gate logs-and-continues on inet-only at `pkg/daemon/daemon_transit_gate.go:366-373` |
| Existing gate actuation writer is `writeTransitGateLocked`/`reassertTransitGate`, with no bare writers except the close-only post-exit cleanup process | `pkg/daemon/transit_gate_tick_9725.go:56-104`, `pkg/daemon/daemon_system.go:992-993`, `pkg/daemon/daemon_apply_dataplane.go:178,1210` (delta C29) |
| **r6 proposal:** split apply-locked/background entries, require `applySem → transitGateMu`, and route both through a proposal helper named `reassertTransitGateLocked`; the close-only cleanup exception remains explicit | **PROPOSAL; exact ownership and lock order are specified in §2.2; the proposal must bind to the master `reassertTransitGate` writer above** |

### 2.2 Divert proposal (PROPOSAL — exact, checkable, T12-pinned)

New table `xpf_ipsec_divert` (PROPOSAL name; S3 may rename with T12 updated
same-change), installed on **both inet and bridge families** for the forward
leg and on the input hooks. The two-family requirement is load-bearing: each
family gets the same forward base-chain placement. Inet input captures routed
host-bound xfrmi plaintext with the ownership `iifname == stN` match; bridge
input is a continuous quarantine-only chain (no daddr match and no q0 path),
so an xfrmi bridge-port membership cannot open an unadjudicated host-bound
race.

- `forward` chain in **inet and bridge**: base chain, hook forward, type filter,
  priority **P_divert = -175** (PROPOSAL; numerically below the shipped fence
  filter priority 0 and outside the conventional mangle priority; S3 MUST pin
  exactly one and T12 MUST assert no same-priority forward/input base chain in
  either family). Rules, in order:
  1. `iifname == <stN> → queue num <Q_{family,forward,stN}>` (**NO `bypass`
     flag**) — one rule per admitted tunnel. `<stN>` comes from the
     ownership-keyed divert oracle `SecureTunnelNetdevForRef ∪ liveXfrmNetdevs`
     (delta C52; snapshot union at
     `pkg/dataplane/userspace/interfaces.go:856`), NOT lexical `st*` (unowned
     `st5` never diverted, T18). The queue handle is provenance-specific; see
     the binding contract below.
  2. No other rules. No ACCEPT, no DROP, no mark, no NAT. Chain policy is
     ACCEPT (fall-through) so non-matching traffic continues to the
     corresponding family fence.
- **Fail-closed queue semantics:** neither family/hook may use nftables
  `queue ... bypass`. If the listener is absent, closing, or being rotated,
  a matching xfrmi packet must not fall through to ACCEPT; it is held until
  the queue/default-drop path or explicit supervisor DROP. T12 kills any
  implementation whose listener-death mutant forwards a matching packet.
  `pkg/nfqueue/nfqueue.go:59-65,164-168` pins userspace closed/timeout and
  explicit no-FAIL_OPEN/drop-fail-closed semantics; the kernel no-listener/
  default-drop behavior is a required S3/T12 live-netns proof, not an assumed
  bypass.
- **`input` chain in inet**: base chain, hook input, type filter, priority
  **P_divert = -175** (before inet lo0/host-inbound/gap priorities 0/10/11,
  whose ordering is pinned at `pkg/nftables/netlink_installer.go:25-34`).
  Match is `iifname == <stN>` → queue num `<Q_{inet,input,stN}>` **only for an
  admitted, census-proven non-VRF-enslaved xfrmi**. The input hook has already
  established local delivery, so this rule MUST NOT depend on a separately
  replicated `daddr ∈ <local-address-set>`; stale/capacity-missed address
  state must not make an eligible xfrmi host-bound packet fall through. A
  VRF-master observation is refusal/fencing, never a broadened match.
  listener remains present while the gate is closed or tunnel DOWN: in that
  quarantine mode every matching row is DROP-and-count, never q0; only an
  OPEN, fully committed generation may admit an explicit host-input policy
  verdict. No-listener/default-drop is still fail-closed.
- **VRF/l3mdev input refusal (PROPOSAL; S3 owns):** the `iifname == stN`
  rule is intentionally **not** widened to `iifname == <VRF-master>`: the
  kernel has replaced `skb->dev`, so a master match would overcapture
  unrelated host traffic and would not restore xfrmi provenance. Before
  admission, and again before every OPEN, S3 resolves `Attrs().MasterIndex`;
  any VRF/l3mdev master rejects that stN. On rejection the canonical
  `xpf_hostinbound` projection emits an explicit master/default-deny fence
  before service accepts (or rejects the whole master configuration if it
  carries unrelated accepted services), and emits no stN/service ACCEPT for
  the refused tunnel. For a runtime discovery on a master that already
  carries live accepted services, r6 chooses **fence-anyway**: S3 does not
  preserve those services, installs the master/default-deny fence across the
  shared master, raises a CRITICAL shared-master alarm/evidence row, and holds
  the tunnel DOWN until the master is detached and a fresh admission succeeds.
  The gate remains closed/DOWN and the input listener is DROP-only. V1 stops at
  this inet INPUT twin: bridge INPUT remains the VRF-immune quarantine below,
  and both inet/bridge FORWARD divert paths remain the existing slave-visible
  ownership/fence proof, not a VRF-match fix. This is host-input fencing, not a
  VRF capture or q0 permit.
- `input` chain in **bridge**: base chain, hook input, type filter, the same
  **P_divert = -175** (before any existing bridge input policy chain). Match
  is `iifname == <stN>` → queue num `<Q_{bridge,input,stN}>`, with no
  destination-set or L3 re-entry predicate. Chain policy is ACCEPT for
  nonmatching frames; every matching bridge-input row is DROP-and-count and
  NEVER q0-reinjected. This quarantine chain remains installed while the
  transit gate is armed **and closed**, so it covers startup and the
  pre-notification/topology-change window.
- **Capture provenance and PF binding (PROPOSAL; S3/T12 must prove):** queue
  numbers are never concurrently shared across family or hook; finite numbers
  may be reused only after retirement quarantine and with a new queue epoch.
  Each admitted tunnel gets `Q_{inet,forward,stN}`, `Q_{inet,input,stN}`,
  `Q_{bridge,forward,stN}`, and `Q_{bridge,input,stN}`; the allocator key is
  `(generation, family, hook, owner, stN)`, and all four handles participate
  in rotation, retirement quarantine, per-tunnel fairness, and queue-depth
  accounting.
  The inet handles PF-bind `AF_INET` + `AF_INET6`; both bridge
  handles PF-bind `AF_BRIDGE`/`NFPROTO_BRIDGE`. The provenance validator
  normalizes either `AF_INET` or `AF_INET6` to the nft `inet` origin (and
  accepts only `AF_BRIDGE` for bridge origins), then checks
  `NFQA_PACKET_HDR.hook` against forward/input. An inet PF-bind/install failure
  is tunnel-DOWN. A bridge-only PF-bind/install failure is **degraded** under
  the `ErrTransitBarrierBridgeUnsupported` precedent: retain the bridge fence/
  quarantine and chain-presence/nonmatching-traffic proof, make no bridge
  packet-receipt claim, and keep routed-inet capture available
  (`pkg/nfqueue/nfqueue.go:192-202`; `pkg/nftables/transit_barrier.go:39-43`).
  Current `Packet` exposes queue ID/payload but not family/hook
  (`pkg/nfqueue/nfqueue.go:315-343`), while `parsePackets` discards
  `nfgen_family` and `parseOnePacket` retains only packet ID from
  `NFQA_PACKET_HDR` (`pkg/nfqueue/nfqueue.go:620-673`). S4 MUST extend the
  parser/API to preserve and validate `{nfgen_family, NFQA_PACKET_HDR.hook}`
  against the queue registry's immutable `CaptureOrigin`; a mismatch is
  DROP-and-count and never q0. This validation is required even with
  provenance-specific queue IDs so a kernel family/hook delivery mistake
  cannot turn bridge quarantine into routed re-entry. `CaptureOrigin` also
  carries the generation's owned `stN` ifindex; S4 preserves and validates
  `NFQA_IFINDEX_INDEV` (or the equivalent netlink ingress-ifindex attribute)
  against it. Device delete/recreate or name reuse with a different ifindex
  is DROP-and-count, never an old-owner disposition; T12 injects that
  delete/recreate/name-reuse mutant.
- The **bridge forward** rule is `iifname`-only and therefore chain-valid even
  for a non-IP bridge frame. If S3 adds an L3 refinement, bridge
  `ether type`/L3 guards MUST be family-valid and MUST NOT accidentally match
  a non-IP frame. A nonmatching bridge frame continues to the bridge fence;
  any captured bridge-forward xfrmi row is DROP-and-count (§2.4), never q0.
  The bridge input quarantine above has no daddr predicate and is likewise
  DROP-only; it remains installed independently of topology census results.
  The runtime guard `checkXfrmiTopologyLocked` (owner: S3, in the
  authoritative transit gate helper) is defense-in-depth and forces forward
  gate/tunnel-DOWN on bridge membership or VRF/l3mdev enslavement; for VRF it
  also requires the inet INPUT master/default-deny fence. It is not a
  bridge-input safety mechanism or a VRF-master capture mechanism. This is
  fail-closed scope, not a new permit.

- **Topology guard and actuation owner (PROPOSAL; S3 implementation slice):**
  `checkXfrmiTopologyLocked` lives beside
  `writeTransitGateLocked`/`reassertTransitGateLocked` in
  `pkg/daemon/transit_gate_tick_9725.go:56-104`; the apply-locked and
  background entries call that locked helper under `transitGateMu` before every
  open, not only at initial startup. It reads
  `transitGateLinkList` seam (same `netlink.LinkList` truth pattern as
  `pkg/daemon/daemon.go:1691-1694`), identifies every `xfrm`/`*netlink.Xfrmi`
  link, follows `Attrs().MasterIndex`, and rejects any link whose master is a
  bridge **or VRF/l3mdev**. VRF rejection is the census backstop to the
  pre-admission rule: it closes the gate, refuses the tunnel, and requires the
  safe host-input master/default-deny fence from the input contract; it does
  not pretend a VRF-master match captures the xfrmi. The same census asserts
  daemon-owned `xpf-usp1` has no master (`MasterIndex == 0`); an enslaved
  outlet closes/DOWNs the gate because q0 re-entry would route through the
  main table, not the selected domain. Census error, incomplete link kind,
  unresolved master, or an unresolved `D_usp1` identity is `unsafe/unknown`,
  never safe. The existing SecureTunnel exclusion is ownership-or-device-kind
  and explicitly does not test bridge or VRF membership
  (`pkg/dataplane/userspace/ingress_exclusions.go:150-158`), so it MUST NOT
  substitute for this guard.
- **Host-input fence owner, lock order, and active overlay (PROPOSAL; S3/S4
  implementation slice): `applySem` is the outer serialization owner for every
  normal host-inbound render, config apply, and topology-close fence
  publication. The apply-locked entry `reassertTransitGateApplyLocked` is
  called from `applyConfigLocked`/normal host rendering only while the caller
  owns `applySem`; it asserts/reuses that ownership and acquires
  `transitGateMu` second. The background entry `reassertTransitGateBackground`
  has two modes. For a watcher-classified relevant topology change affecting
  an admitted `stN`, selected `xpf-usp1` outlet, or transit master—including
  RTM_DELLINK/detach that removes a required `stN`/outlet or invalidates the
  ready predicate—or a close wakeup already tied to unsafe/unknown census, it
  first calls `revokeTransitPermitNonblocking`, the lock-free full-record CAS:
  `OPEN→CLOSING` increments `permit_epoch`, while a distinct event observed
  during CLOSING advances `close_request_seq` without a second epoch increment.
  Only a narrowly classified safe-removal (removing the offending unsafe
  relationship/object while already CLOSING, or a proven irrelevant object)
  and unrelated RTM_NEWLINK/DELLINK noise use the census-only path; required
  link loss is never safe-removal and pre-revokes even when `applySem` is busy.
  A healthy periodic tick whose census confirms an OPEN record and unchanged
  safe topology likewise does **not** revoke or bump the epoch; it only
  boundedly acquires `applySem`. All modes then invoke the same
  `reassertTransitGateLocked` helper; that helper takes `transitGateMu` but
  never `applySem`. No path may hold `transitGateMu` while waiting for
  `applySem`. If a pre-revoking mode cannot acquire `applySem`, its permit
  record remains
  CLOSING, it records `host_fence_owner_busy`, and it reasserts without claiming
  the forward gate or INPUT fence is closed or tunnel supervision DOWN. If a
  census-only mode times out before acquiring `applySem`, no permit CAS occurred:
  its existing record state/epoch/sequence/key/watch (OPEN or already CLOSING)
  remains unchanged, it records the same owner-busy evidence, and it reschedules without
  any gate/DOWN claim.
  The daemon stores an active
  `HostInputFenceOverlay{master_set,generation,permit_epoch,close_request_seq,closeRequestKey,watchGeneration,state}` under that
  owner. Every normal render MUST merge the active overlay into the
  `xpf_hostinbound` generation before service rules and the leading
  established/related ACCEPT, and before `InstallHostInbound`; no config apply
  may replace or delete an active overlay outside the canonical detach-clear
  transaction below. Before rendering, the writer
  snapshots `(permit_epoch,close_request_seq,closeRequestKey,watchGeneration)`
  from the atomic `permitRecord` and active overlay, then compares that tuple immediately before
  netlink install. A pre-install mismatch from a concurrent event or snapshot
  publish discards the local render and reruns census/re-render. After install
  and ruleset read-back, it compares the tuple again before accepting the
  fence/conntrack publication ACKs. A post-install mismatch cannot undo the
  live single `xpf_hostinbound` table synchronously: it remains a conservative
  fence for its old covered master set only, records
  `host_fence_supersession_debt`/`host_fence_unacked`, and keeps overall state
  CLOSING with no fail-closed/DOWN claim. The retry renders the newer merged
  overlay through one atomic `InstallHostInbound` replacement
  (`pkg/nftables/netlink_installer.go:100-103,148-166`), which supersedes the
  stale table; on replacement failure the old conservative fence remains and
  debt retries, while success replaces it atomically before the newer
  read-back/conntrack ACKs. No two named generations coexist and no stale table
  is separately removed.
- **Detach-triggered overlay retirement (PROPOSAL; S3 canonical owner):** a
  topology watcher may request retirement only after a fresh census proves that
  a master covered by the active overlay detached and computes the current
  relevant `master_set` (possibly empty; if another covered master remains, the
  set is narrowed rather than cleared wholesale). The
  `reassertTransitGateApplyLocked`/`reassertTransitGateBackground` owner,
  under the existing `applySem → transitGateMu` order, performs the only
  mutation through `clearHostInputOverlayOnDetachApplyLocked`; the watcher and
  ordinary config renderer never mutate or delete the overlay directly. It
  keeps the permit CLOSING and listeners DROP-only, marks
  `host_fence_clear_pending`, and snapshots the permit/overlay generation.
  While the old conservative table remains live, it first requires conntrack
  revocation ACK for the old covered set, then renders the current-set
  replacement through the one atomic `InstallHostInbound` transaction and
  requires nft install/read-back ACK. A pre-install tuple mismatch, flush
  failure, or definite pre-commit install failure leaves the old overlay/table
  live, records `host_fence_clear_debt`/`host_fence_unacked`, raises CRITICAL
  evidence, and retries. A post-install tuple mismatch after confirmed
  install/read-back leaves the candidate table known live; it is conservative
  only for the `master_set` actually rendered by that candidate (which may be
  narrowed or empty). It retains the logical old overlay/debt in memory,
  records `host_fence_supersession_debt`/`host_fence_unacked`, and retries the
  newer replacement without claiming fail-closed/DOWN authority. An ambiguous
  install ACK or ambiguous read-back leaves kernel table state unknown (old or
  candidate); it makes no liveness claim about either table, retains the
  overlay logically active in memory and state CLOSING with the same debt,
  reconciles via read-back, and re-fences if a live superseding table plus
  reattach/concurrent evidence requires it. No stale overlay is separately
  removed; re-census/render retries until convergence. Only after both ACKs
  does the owner retire the old `master_set`, clear the pending/debt alarm,
  and permit reopen after a fresh safe census, current watch snapshot, and
  expected-record OPEN CAS. A normal config apply must continue merging
  whichever overlay is active throughout this transaction.
- **Established-flow fence commit (PROPOSAL; S3/S4):** the host-fence
  publication has two required ACKs: nft install/read-back and revocation of
  every established/related direct-host flow covered by the offending master
  (including all services on a runtime shared master). S3 extends the existing
  host-inbound conntrack flush path
  (`pkg/daemon/daemon_nft.go:776-798`) with the master/overlay generation,
  waits for its completion, and records the exact failed request in the
  existing `hostInboundConntrackDebt` retry state and failure counter
  (`pkg/daemon/daemon.go:1025-1045`). A flush timeout, error, or ambiguous
  completion leaves the active overlay installed but marks
  `conntrack_fence_debt`/`host_fence_unacked`, raises CRITICAL evidence, and
  keeps close in CLOSING/stuck-DOWN: no post-close host DROP claim or OPEN is
  permitted until a later flush ACK/read-back clears the debt. This prevents
  the table's leading established/related accept from preserving a service
  after the fence decision.
- **Unsafe topology transition:** if the census is unsafe/unknown,
  For a watcher-classified relevant RTM change—including a required-link
  DELLINK that removes an admitted `stN`/outlet or invalidates the ready
  predicate (but excluding only a safe-removal already CLOSING or a proven
  irrelevant object)—a close wakeup tied to unsafe/unknown census, or a
  periodic tick whose preliminary census sees changed/unsafe topology, it
  first invokes `revokeTransitPermitNonblocking`, the lock-free full-record
  `permitRecord` CAS, before boundedly acquiring `applySem` and invoking the
  locked helper.
  An apply-locked `reassertTransitGateApplyLocked` call reuses the caller's
  already-held `applySem` before taking `transitGateMu`. For a VRF/l3mdev
  the first actuation for a VRF/l3mdev attach is an explicit **S3-owned**
  revoke confirmation: the full-record CAS increments `permit_epoch` only on
  `OPEN→CLOSING`, advances `close_request_seq` for a distinct CLOSING event,
  and remains CLOSING on retries. This pre-lock CAS cancels new input
  ACCEPT/REINJECT authorization before any fence ACK; no entry may reopen while
  fence or conntrack debt remains. The first locked actuation after that revoke
  is an inet INPUT-fence before tunnel supervision is DOWN:
  (1) snapshot the offending master, current host-inbound generation, and
  shared-master service set; (2) render the canonical `xpf_hostinbound`
  master/default-deny fence using the daemon's host-inbound render path
  (`pkg/daemon/daemon_nft.go:521-545,558-582`,
  `pkg/nftables/netlink_hostinbound.go:27-78`); (3) install/replace it through
  the nft netlink writer; (4) wait for install ACK plus ruleset read-back under
  the same lock; and (5) revoke all established/related direct-host entries
  covered by the master/overlay, waiting for conntrack completion/read-back.
  `T_hostfence` is a hard S3/G2-selected deadline inside the 50ms close budget;
  both ACKs are required. This fence transaction is the publication boundary:
  traffic during render/install may receive the prior host-inbound verdict, but
  traffic after both ACKs must hit the master/default-deny DROP; no post-close
  DROP claim is made before both ACKs.
  An install/read-back or conntrack-revocation failure or timeout immediately
  triggers bounded retry/reassert of an unconditional host-input default-deny
  transaction and a CRITICAL `host_fence_unacked` alarm. Only a successful
  targeted or fallback fence ACK plus conntrack ACK permits the state to be
  called fail-closed/DOWN; if the targeted and fallback transactions cannot ACK,
  the forward gate is forced closed but supervision remains
  `stuck-DOWN/unsafe-host-fence`, retries/reasserts on the periodic backstop,
  and never reopens or claims a post-close host DROP until a later ACK.
  The r5 per-queue emission gates remain `OPEN` for those retained input
  queues so terminal DROP verdicts can commit; the CLOSING permit makes every
  new or stale input ACCEPT/REINJECT fail validation and commit exactly one
  terminal DROP immediately, and input listeners enter DROP-only mode at this
  CAS; no such queue verdict waits for fence/conntrack ACK.
  After permit revocation, the same locked close path installs the unconditional
  forward barrier and writes forwarding
  sysctls false in barrier-before-sysctl order
  (`pkg/daemon/transit_gate_tick_9725.go:82-104`,
  `pkg/daemon/daemon_transit_gate.go:390-411`). It then transitions only the
  forward queue emission gates `OPEN → CLOSING` to stop new receives, obtains
  the source-cutoff/drain ACK over the now-finite in-flight set (r5 §12.3),
  transitions those forward gates `CLOSING → CLOSED`, and only then tears down
  the bridge-forward and inet-forward capture queues and reports affected
  tunnel supervision **DOWN**. The inet-input and bridge-input quarantine
  chains/listeners remain installed. While closed/DOWN, both input listeners
  issue DROP-and-count for matching xfrmi rows; this plan does NOT claim
  immediate SA/xfrmi destruction. For a VRF attach specifically, the inet
  INPUT `iifname == stN` row is nonmatching until the host-fence publication
  takes effect; a packet not yet covered by that fence therefore has the
  bounded status-quo host-inbound outcome described below, never a claimed VRF
  capture. Any matching/stale q0 descriptor is rejected by the CLOSING permit
  and commits one terminal DROP immediately. Before the fence ACK, status quo
  may occur for packets outside the published fence; after the fence ACK but
  before the conntrack ACK, the master/default-deny rules may show their DROP
  verdict, but close remains CLOSING and no post-close DROP or tunnel-DOWN claim
  is allowed. Input listeners are already DROP-only from the CAS; only after
  both ACKs are committed are the post-close host-fence and close state
  authoritative. The permit epoch MUST NOT reopen until a fresh safe census,
  host-fence publication ACK, and complete inet-forward + inet-input +
  bridge-forward + bridge-input install commit.
  Startup remains closed by `closeTransitUntilAttached`; its first reassert
  performs this census and verifies the quarantine chain is already installed.
- **Topology-change recheck:** extend
  `transit_gate_link_watch_9848.go:27-95` so RTM_NEWLINK and RTM_DELLINK
  (bridge-master and VRF/l3mdev-master attach/detach included) are classified
  by affected admitted `stN`, selected outlet, and ready-predicate ownership.
  The watcher loads an immutable `atomic.Pointer[TransitWatchSnapshot]` published
  by apply/config ownership; each snapshot carries its generation, admitted
  `stN` ifindexes/names/ownership IDs, selected `xpf-usp1` outlet ifindex, and
  transit-master/bridge/VRF-master IDs. It never reads protected daemon maps.
  The watcher atomically loads both the immutable snapshot and the
  `permitRecord`, then compares the snapshot token/generation with the OPEN
  record's `watchGeneration`. A LinkUpdate matching a current relevant ID
  invokes the nonblocking revoke before the locked close. For a potentially
  relevant xfrm/bridge/VRF/l3mdev/master/outlet event, a missing or stale
  snapshot, unresolved ID, or token mismatch conservatively pre-revokes instead
  of waiting for `applySem`; an unrelated unknown ifindex/event is census-only.
  The narrow already-CLOSING/proven-irrelevant safe-removal path also runs
  census-only, then schedules the coalesced reassert without an OPEN/epoch flap.
  The continuously installed inet-input and bridge-input quarantines catch matching
  input during the event race and after tunnel-DOWN. The periodic tick remains the
  backstop for missed events (`pkg/daemon/transit_gate_tick_9725.go:91-104`).
  The attach-to-close race is explicit: an INPUT packet arriving after the
  kernel VRF/l3mdev attach but before the event watcher acquires
  `transitGateMu` can fall through to the pre-existing host-inbound table and
  receive only its **status-quo host-inbound verdict**; it is not claimed as
  captured or policy-adjudicated by 9506. The window is bounded by event
  delivery plus the locked close, with the periodic tick as the missed-event
  backstop; the permit CAS is already CLOSING: any queued/stale ACCEPT or
  REINJECT fails validation and becomes one terminal DROP, and input listeners
  are DROP-only immediately. Before the fence ACK, status quo may occur outside
  the published fence; after the fence ACK but before the conntrack ACK,
  master/default-deny may be visible, but no post-close DROP or tunnel-DOWN
  claim is allowed; after both ACKs, the host fence and post-close state apply.
  T12/G2's live VRF cell sends host-bound packets on both sides of that
  boundary and reports the pre-close status-quo verdict separately from post-close DROP.
  T12 injects startup, RTM_NEWLINK attach, required-link RTM_DELLINK/detach,
  census-error, safe-removal while already CLOSING, proven-irrelevant
  RTM_NEWLINK/DELLINK noise, and an in-flight host-input verdict race.
  The snapshot classifier must pre-revoke for a relevant current ID and for a
  potentially relevant xfrm/bridge/VRF/master/outlet event with an
  unknown/stale-generation or missing snapshot while OPEN; a proven-irrelevant
  noise event must leave the full `(OPEN,e,s,k,w)` record and queue permits
  unchanged.
  T12 shuffles the injected LinkList order within repeated healthy observations
  and separately within repeated identical unsafe or repeated UNKNOWN observations.
  Healthy observations allocate no close request; within each unchanged unsafe/UNKNOWN
  case, the sorted `closeRequestKey` and shared event sequence remain identical,
  with no epoch churn or extra request. A changed `readyResult` (healthy versus
  unsafe versus UNKNOWN) is a different key and is not conflated.
  It also publishes a new immutable watch snapshot while CLOSING under
  `applySem`, then asserts pointer-swap followed by the exact
  `watchGeneration` CAS; a pointer-only update and an OPEN CAS with `w_old`
  both fail, while the fresh-census/both-ACK CAS with `w_new` is the only
  allowed reopen.
  With `applySem` deliberately held, a healthy periodic tick and proven-
  irrelevant noise event must time out without any revoke CAS: the OPEN
  `(e,s,w)` record and queue permits remain unchanged, owner-busy is recorded,
  and no gate/DOWN claim is made.
  A required-link DELLINK must pre-revoke before `applySem`; proven-irrelevant
  noise uses census-only and, when safe, leaves `(OPEN,e,s,k,w)` and queue permits
  unchanged. Safe-removal while already CLOSING leaves the existing CLOSING
  record unchanged (no extra epoch/seq); it may reopen only through the fresh
  census/both-ACK expected-record CAS. For a VRF attach, an S3-owned close
  barrier pauses after host-fence render but before netlink
  publication ACK; traffic to the shared master during that publication must
  report the prior host-inbound verdict and no close/DOWN claim. The permit CAS
  is already CLOSING, so queued/stale ACCEPT or REINJECT attempts become terminal DROP
  and input listeners are DROP-only immediately. After the fence ACK/read-back
  but before the conntrack ACK, the same traffic may hit the master/default-deny
  DROP, but close remains CLOSING and no post-close DROP or tunnel-DOWN claim is
  allowed. After both ACKs, the post-close host-fence state is authoritative;
  input DROP-only behavior was already effective at CAS; barrier-before-sysctl,
  forward emission gates `OPEN→CLOSING`, drain/cutoff ACK, forward gates
  `CLOSING→CLOSED`, and DOWN/teardown. T12 configures an accepted service on
  the live shared master and asserts the chosen
  fence-anyway disposition: that service is also DROP-counted, with the
  CRITICAL shared-master alarm/evidence row. It injects targeted
  `InstallHostInbound` failure, ACK timeout/read-back mismatch, and fallback
  default-deny failure; each must assert retry/reassert, `host_fence_unacked`,
  `conntrack_fence_debt`, stuck-DOWN/no-reopen, and no post-close DROP claim
  until a later fence+conntrack ACK. T12 holds `applySem` while injecting
  RTM_NEWLINK: the background entry must perform one ABA-safe atomic record CAS
  to `(CLOSING,epoch+1,event_seq,k,w)` before its bounded acquire; retries of the
  same event must observe the same CLOSING record without another epoch
  increment, record owner-busy without claiming the gate closed, and complete
  after release. It also invokes the apply-locked entry from `applyConfigLocked`
  and the background entry in separate runs, asserting one `transitGateMu`
  helper and no self-deadlock.
  T12 interleaves event A with `eventSeq=1` and event B with `eventSeq=2` in
  both arrival orders while CLOSING, then retries A after B; the record must
  retain `close_request_seq=2`, never regress to 1, and never increment
  `permit_epoch` more than once for the close. A duplicate B is a no-op. The
  same run interleaves RTM, close-wakeup, and first-unsafe-tick requests; all
  sequences must come from the daemon-wide `closeEventSeq` without collisions,
  and stale lower-sequence retries must remain no-ops.
  T12 runs two host-fence render races with the tuple
  `(permit_epoch,close_request_seq,closeRequestKey,watchGeneration)`: (a) pause before
  netlink install and inject a relevant event, requiring the pre-install tuple
  check to fail and discard the local render/re-census; then (b) inject a
  second event after install/read-back but before publication ACK. The
  post-install mismatch must leave the single stale table live as a conservative
  fence for its old covered master set only, record
  `host_fence_supersession_debt`/`host_fence_unacked`, and keep state CLOSING
  with no fail-closed/DOWN claim. A definite pre-commit replacement failure
  must keep that old conservative fence; a successful `InstallHostInbound`
  replacement must atomically supersede it with newer read-back/conntrack ACKs
  and no two named tables or stale removal.
  T12 also detaches the currently covered shared master while CLOSING. The
  canonical owner must recompute the current set, keep the old conservative
  overlay live while obtaining the old-set conntrack ACK, atomically install
  the replacement, and obtain its nft read-back ACK before retiring
  `master_set` and clearing `host_fence_clear_pending`/clear debt. A flush or
  definite pre-commit replacement failure retains the old table and CRITICAL
  retry evidence; if ACK loss occurs after replacement, which may have committed,
  kernel table liveness is unknown, so the test must never assert retained-old or
  candidate liveness: retain the logical overlay/debt in memory, stay CLOSING,
  reconcile by read-back, and converge by re-fencing when concurrent reattach
  evidence requires it. A concurrent normal apply must merge the active
  overlay. Only the successful clear transaction plus fresh safe census/current
  watch snapshot may feed the expected-record OPEN CAS.
  T12 explicitly submits an atomic replacement and loses its ACK/read-back
  before commit status is known, then concurrently reattaches the covered
  master before reconciliation completes.
  It must assert debt, logical-overlay retention, CLOSING, and no
  fail-closed/DOWN or post-close DROP claim; it must make no retained-old or
  candidate-table liveness assertion. Read-back must reconcile the kernel state,
  and the retry path must converge to a re-fence when the reattach is live,
  never to a stale OPEN.
  T12 drives safe-open interleavings: (a) revoke
  immediately before the OPEN CAS, (b) inject a new topology event after the
  final census but while CLOSING and immediately before OPEN CAS, and (c)
  revoke immediately after the OPEN CAS but before any stale descriptor
  validation. Cases (a)/(b) must fail the expected full-record
  `(CLOSING,e,s,k,w)` CAS and retry. In (b), the event must update
  `close_request_seq` even if `permit_epoch` stays unchanged, making
  `(CLOSING,e,s,k,w)` fail. In (c), the post-CAS revoke must advance
  `(OPEN,e,s,k_old,w) → (CLOSING,e+1,s_new,k_new,w)` before stale ACCEPT can validate;
  that ACCEPT becomes one terminal DROP. Repeated healthy periodic ticks on
  unchanged safe topology must leave the full `(OPEN,e,s,k,w)` record and queue
  permits unchanged; a tick may revoke only after its preliminary census
  identifies a changed/unsafe topology generation.
  After a successful OPEN with `k_safe`, T12 reintroduces the identical unsafe
  fingerprint via a distinct RTM event; the watcher must allocate a fresh
  `eventSeq`, revoke OPEN despite the recurring key, and reject any stale OPEN
  CAS. It also holds netlink install longer than one tick while repeated ticks
  observe the same unsafe/UNKNOWN key; they reuse one sequence, do not starve
  the tuple checks, and converge to the newer fence/conntrack ACK.
  T12 concurrently drives a normal config apply through `applyHostInboundFilter`
  while this close
  is paused, and keeps an established/related host session on the shared master.
  The apply must merge the active overlay and never erase an ACKed deny;
  conntrack revocation must terminate the established session.
  A flush failure leaves exact retry debt/alarm and no close claim. A stale ACCEPT
  attempt must become exactly one terminal DROP and only a fresh OPEN permit
  epoch may ACCEPT. It also asserts both input-listener DROP outcomes
  during/after the event and no reopen until all four provenance queue classes,
  both family fences, host-fence publication ACK, and conntrack ACK are
  committed. No statement in this plan treats T12 itself as the runtime guard.
- Untouched (asserted, T12-pinned with divert live): `oif == stN` outbound,
  SNAT/`accept_local` ingress identity via XDP pinholes
  (`pkg/daemon/daemon_run_bringup.go:676-677`), #7409 reinject importer
  (`pkg/routing/fibimport.go:16`) + #7437 event-driven republish
  (`pkg/daemon/daemon_route_listener.go:16-23`), `xpf-usp0`/`xpf-usp1`
  outlets, host-inbound/lo0/gap tables, RST-suppression output chain
  (`pkg/nftables/rst_suppress.go:114-116`).
- Queue handles come from the r5 per-daemon allocator under the expanded
  provenance key `(generation, family, hook, owner, stN)`; each
  `(family,hook,stN)` handle has `(number, epoch)` identity and reuse
  quarantine. Rotation builds the new rule+handle generation and publishes
  the inet+bridge replacements in **one cross-family netlink transaction**
  (PROPOSAL; S3 must bind both family updates to the same transaction). The
  transaction touches the DIVERT table only; the fence table is never in it.
  If the netlink API cannot provide that boundary, the fallback is an explicit
  staged fail-closed protocol: revoke the permit epoch and keep the forward
  gate closed; install the inet replacement, then the bridge replacement, while
  both generations remain quarantine-only; activate neither as OPEN until both
  succeed; on any failure remove the staged family and restore the old
  generation, and force tunnel-DOWN if rollback itself fails. A mixed
  generation may exist only in this closed/quarantine state, never with an
  ACCEPT or q0 permit. Each staged netlink operation has a hard
  `T_nl` deadline that S3/G2 MUST choose and record before the spike
  (including Flush-style calls that can block): a watchdog-visible breach
  aborts staging, starts rollback, and forces tunnel-DOWN if rollback cannot
  complete within its own `T_nl` budget. G2 prices the rotation outage as two
  `T_nl` deadlines plus rollback/drain, and T12 injects failure between
  encodings and a stalled operation to assert no mixed generation becomes OPEN.
- **Rotation triggers, frequency, and staging scope (PROPOSAL; S3/S4/T12
  must pin):** triggers are (a) tunnel admission/removal or a change to the
  desired tunnel-owner set, (b) `stN` ifindex/name/ownership/bridge-membership
  change, including RTM_NEWLINK/RTM_DELLINK, (c) queue-listener retirement,
  rebind, or allocator-epoch quarantine, and (d) a policy/FIB/config-snapshot
  generation change that alters the selected route domain or divert ownership.
  A per-tunnel trigger starts **one global shared-outlet rotation**; all four
  provenance classes and each required family's **divert handles** stage only
  after the required family fences are already committed (both families on the
  supported path; the inet fence in the documented degraded branch). The
  rotation path stages divert handles only and never writes/stages a fence
  table; no tunnel may remain OPEN on the old generation while another tunnel
  uses the new one.
  Events coalesce behind at most one in-flight rotation; there is no periodic
  rotation (the periodic census tick is only a missed-event backstop). A
  failed commit/rollback retry remains part of that trigger's rotation, not a
  second budgeted rotation. G2/T12 report trigger class, coalesced frequency,
  and outage duration for every rotation and enforce one per-rotation budget:
  two `T_nl` deadlines plus source-cutoff/drain and rollback; any over-budget
  or mixed-generation OPEN fails.
- **Epoch/owner mapping (PROPOSAL; S3/S4 must pin):** `queue_epoch` is the
  allocator's `(number,epoch)` handle identity and changes on queue rotation or
  retirement. `permit_state` and `permit_epoch` form one atomic authorization
  pair; the same atomic permit record carries monotonic `close_request_seq`,
  `closeRequestKey`, and `watchGeneration`, the generation/token of the
  immutable watcher snapshot bound to an OPEN permit. S3 pins the representation
  as `atomic.Pointer[permitRecord]` to an immutable
  `{state,permitEpoch,closeRequestSeq,closeRequestKey,watchGeneration}`
  snapshot: every changed record allocates a fresh snapshot, readers load the
  pointer, and no field is mutated in place. Go GC keeps a reachable expected
  snapshot from pointer reuse during `CompareAndSwap`, making the full-record
  CAS ABA-safe. `closeRequestKey` is an immutable canonical value containing
  `{readyResult,watchGeneration,sortedRelevantTuples}`; each tuple is the
  fixed `(kind,ifindex,masterIndex,name,owner)` identity, sorted
  lexicographically before comparison. Equality compares the complete sorted
  vector and ready result (no hash or LinkList-order-dependent serialization);
  an `UNKNOWN` key is one persistent unknown episode, not a new key per
  periodic tick. A daemon-wide `atomic.Uint64 closeEventSeq` is the sole
  allocator shared by the RTM watcher, close wakeups, and the first
  changed/unsafe periodic census. It increments only for a new event identity
  or materially new key; event retries carry their stored sequence, while
  periodic/census retries for the same key reuse it. A newly classified
  relevant event while OPEN therefore gets a fresh sequence after a prior
  successful reopen. The revoker computes `s_new = max(current.close_request_seq,eventSeq)`; a same-key
  periodic/census retry while CLOSING, or any `eventSeq <= current`, is a
  no-op. Otherwise, a strictly newer sequence/key allocates/CASes a changed
  record. `revokeTransitPermitNonblocking` preserves `w` while writing `k_new`
  through an ABA-safe full-record CAS:
  `(OPEN,e,s_old,k_old,w) → (CLOSING,e+1,s_new,k_new,w)` for `s_new > s_old`,
  including `k_new == k_old` for a new OPEN-state event, while
  `(CLOSING,e,s_old,k_old,w) → (CLOSING,e,s_new,k_new,w)` updates freshness
  without another epoch increment. Same-key or out-of-order retries cannot
  regress `s` or allocate per-tick requests and are idempotent. The locked
  helper owns all other permit-state transitions under `transitGateMu`.
  Reopening is allowed only after a fresh safe census, both fence/conntrack
  ACKs, and a current watcher snapshot whose generation is `w`; its publication
  must CAS the expected `(CLOSING,e,s,k_old,w)` record to
  `(OPEN,e+1,s,k_safe,w)`, where `k_safe` includes the fresh SAFE census
  outcome, after those final checks. A watcher token, key, or new event mismatch
  makes that CAS fail and forces retry; `transitGateMu` alone cannot publish a
  stale OPEN.
  Watch-snapshot publication is coupled, never pointer-only: under `applySem`, a
  publisher first invokes the nonblocking revoke if the current record is OPEN,
  swaps in the immutable snapshot while the permit is CLOSING, then CASes the
  exact `(CLOSING,e,s,k_old,w_old)` record to
  `(CLOSING,e,s,k_new,w_new)`; a failed CAS leaves CLOSING and retries. Every
  later publisher repeats the pre-revoke check before its pointer swap and record
  CAS, so a snapshot token cannot change behind an OPEN CAS.
  The record is the single authorization source for q0
  validation: the validator checks it first, then `queue_epoch`, then
  `snapshot_generation`; any stale tuple gets one DROP.
  The allocator `owner` is the device-ownership identity (the
  `SecureTunnelNetdevForRef ∪ liveXfrmNetdevs` oracle at
  `pkg/dataplane/userspace/interfaces.go:856`), not the per-flow worker
  dispatch function. T12 rotates a device while an old-flow descriptor is
  queued and asserts the old owner cannot consume the replacement handle.
- Integration via `writeTransitGateLocked`/`reassertTransitGateLocked` under
  `transitGateMu` (r5 §12.4 S3 retained; delta C29/C54). Divert install
  failure on inet ⇒ tunnel DOWN. A bridge-only install/PF-bind failure is
  tunnel-DOWN only after S3 proves enslavement and commits bridge as required;
  an unsupported/rejected bridge leg enters the explicit degraded
  fence/quarantine/chain-presence mode above, with no bridge receipt claim and
  routed-inet capture retained.

### 2.3 Ordering proof (divert-before-fence does NOT reopen leave-alone transit)

Claim: with P_divert (-175) < filter (0), and no same-priority base-chain
collision, the divert layer captures ONLY xfrmi ingress for adjudication and
leaves every other transit verdict EXACTLY as the fence alone would render it.

Proof by hook-evaluation order (each step cites the code it depends on):

1. nft hook dispatch evaluates base chains in ascending priority order. The
   repo pins this ordering as a determinism invariant for its input-hook
   chains (`pkg/nftables/netlink_installer.go:25-34`); the same kernel order
   applies to forward-hook chains. Divert at -175 evaluates BEFORE the fence
   at 0 on every forward packet in both inet and bridge. T12 also asserts no
   same-priority base chain in either family; no priority tie exists.
2. Non-tunnel transit (leave-alone, unmanaged, configured-but-unzoned,
   XDP-owned phys, `xpf-usp0`, unmarked `xpf-usp1`, and ordinary bridge
   ports): `iifname` does not match any `<stN>` in the ownership-keyed set, so
   the family-local divert rule does not match, its ACCEPT policy falls
   through without a verdict, and evaluation reaches that family's fence at
   0 with the packet unmodified. The fence then renders its shipped verdict:
   ACCEPT iff `iifname ∈ {tracked XDP}` or `(xpf-usp1, exact mark)`
   (`pkg/nftables/transit_barrier.go:177-195`), else DROP policy. Divert added
   no ACCEPT and no queue; the verdict is bit-identical to fence-alone.
   Leave-alone transit REMAINS DROPPED in both families. ∎ (leave-alone leg)
3. xfrmi FORWARD transit: `iifname == stN` matches the inet or bridge
   forward divert rule → its provenance-specific queue
   `Q_{family,forward,stN}`. Traversal SUSPENDS until userspace issues a
   terminal verdict on the held packet (NFQUEUE hold semantics; `ErrTimeout`
   is a Recv deadline only, hold unaffected,
   `pkg/nfqueue/nfqueue.go:63-65`). The queue registry + parser origin check
   (§2.2) must identify family, hook, and owner before any disposition.
   Three terminal dispositions:
   - DROP verdict → packet dropped, never reaches the family fence. Safe;
     counted as adjudicated-DROP (retained terminal accounting,
     `pkg/nfqueue/nfqueue.go:345-381`).
   - ACCEPT verdict → traversal RESUMES at the next priority (the family
     fence at 0) with the ORIGINAL skb (`iifname` still the xfrmi; NFQUEUE
     ACCEPT does not retarget ingress). The fence has no pinhole for any
     xfrmi (`pkg/daemon/daemon_transit_gate.go:122-124`) → DROP policy drops
     it. **Raw ACCEPT of a diverted forward packet is therefore a
     fence-closed no-op, NOT a permit.** S4 MUST NOT use ACCEPT as the
     forward-permit path; the S3 spike MUST prove this resumption-to-fence
     behavior on both family paths (kill-polarity mutant: if ACCEPT skips the
     fence, the ordering proof is void and the plan KILLS per §9).
   - **inet routed REINJECT only** → userspace issues DROP on the held
     original (cleanup, not authorization) and writes the adjudicated inner
     frame to the marked-queue outlet `xpf-usp1` q0 (§3). The re-entered
     frame arrives at the inet forward hook with `iifname == xpf-usp1` + TC
     mark `0x58465001`, matches the inet fence marked pinhole
     (`pkg/nftables/transit_barrier.go:181-194`), and is ACCEPTED. This is
     the ONLY forward-permit path. It requires successful adjudication,
     the singleton routed domain, structural queue provenance (TC-set mark,
     not userspace-chosen, `userspace-dp/src/slowpath.rs:974-977`), and the
     fence conjunction.
   - **bridge FORWARD is quarantine-only**: q0 is an L3 TUN
     (`userspace-dp/src/slowpath.rs:27-29`), so it cannot preserve the
     captured L2 bridge path. A bridge-family row therefore has no REINJECT
     disposition; it is DROP-and-count (or a raw ACCEPT mutant that resumes
     to and is dropped by the bridge fence, never a permit). No bridge packet
     is sent to q0. This is the explicit safe bridge disposition, not a claim
     of bridge re-entry. ∎ (routed vs bridge tunnel legs)
4. xfrmi INPUT transit (host-bound): the inet input twin at -175 queues before
   inet lo0 (0) / host-inbound (10) / gap (11)
   (`pkg/nftables/netlink_installer.go:25-34`). An inet ACCEPT resumes to inet
   host policy chains **only after an OPEN, fully committed generation has
   explicitly authorized that host-input disposition**; while the gate or
   tunnel is closed/DOWN, the listener issues DROP-and-count. Non-tunnel
   host-bound misses the `iifname == stN` ownership match and falls through
   unmodified. A VRF-enslaved xfrmi is likewise nonmatching at LOCAL_IN after
   l3mdev substitutes the master, so V1 refuses it before admission; after
   runtime detection, the census and ACKed host-input master fence close the
   race; it is never counted as an inet-input capture.
   The bridge input quarantine at -175 queues every owned `stN`; userspace
   issues DROP-and-count only, never q0, and no-listener/default-drop remains
   fail-closed.
   The transit fence is forward-only and
   uninvolved on input (`pkg/nftables/transit_barrier.go:164-175`), while both
   input quarantine listeners remain installed during topology checks and gate
   closure. The inet/bridge FORWARD paths remain slave-visible and are
   unaffected by the V1 input-only refusal. ∎
5. Two writers, four divert hook instances (inet forward, inet input, bridge
   forward, bridge input), no collision: the fence writer owns table
   `xpf_transit_barrier` (delete+recreate per family per install,
   `pkg/nftables/transit_barrier.go:197-225`); the divert writer owns table
   `xpf_ipsec_divert` (atomic rule-handle swap per family, §2.2). Separate
   Fence reassert (`reassertTransitGateLocked`, **r6 PROPOSAL name; master writer:
   `reassertTransitGate`**, `pkg/daemon/transit_gate_tick_9725.go:91-104`) never
   touches divert handles; divert rotation never touches fence handles. A
   concurrent fence reassert + divert rotation is two independent atomic
   batches per family; hook evaluation sees one ruleset snapshot per packet
   (r5 §4.2 capture proof retained). T12 asserts both families' complete
   forward and input rules plus all provenance bindings after every
   interleaving in the rotation fuzz. ∎
Corollary (kill condition): the proof holds IFF (i) P_divert < 0 strictly,
(ii) divert matches ONLY the ownership-keyed stN set in **both-family
forward** chains plus the separate inet-input ownership match and the bridge
input quarantine, (iii) divert emits no ACCEPT/DROP/mark, (iv) NFQUEUE ACCEPT
resumes to the applicable fence (S3-measured on routed forward fixtures and on
bridged forward fixtures only when enslavement step 0 accepts; the degraded
branch proves chain/nonmatching behavior; bridge input has no q0 ACCEPT
disposition),
(v) all required family/hook queue handles, PF binds, parser provenance checks,
and divert table transactions commit together or fail closed, and **(vi) V1's
topology/FIB precondition holds: every admitted xfrmi is non-VRF-enslaved, daemon-owned
`xpf-usp1` is unenslaved, `D_usp1` resolves to the main table, and a VRF or
other non-main attach is refused/fenced with the bounded status-quo race
explicitly measured.** Violation of ANY conjunct that S3 cannot repair by
tightening the match-set, priority, or this refusal/census gate KILLS the plan
(§9) — the deliverable is then the falsifying measurement, not a narrowed
claim.


### 2.4 Both-family bridge leg (unsafe-topology capture conformance; L2 re-entry is not claimed)

The fence installs on inet AND bridge because bridged frames never traverse
the inet forward hook (`pkg/nftables/transit_barrier.go:112-116`). r6 also
installs the divert on **inet and bridge FORWARD** plus an inet INPUT chain
for host-bound xfrmi plaintext and a bridge INPUT quarantine chain at P_divert.
The inet input is an ownership-based host-bound INPUT twin; bridge input has no
daddr match and no q0 disposition. Bridge-family xfrmi packet receipt is a
conformance cell only if S3 enslavement step 0 succeeds: T12 uses an S3-owned,
test-only injectable close-phase barrier (nil/no-op in production) after the
topology guard detects a bridge-master attachment and revokes the permit epoch,
but before forward emission gates transition `OPEN→CLOSING`/source cutoff.
While paused, it observes both bridge listeners and terminal DROP-counts their
packets; release then tears down bridge-forward capture. If enslavement is
rejected, the cell records chain/PF-bind/nonmatching behavior only; this is not
a steady-state G2 workload and the retained bridge-input quarantine remains
DROP-only.
S3 MUST run bridge-enslavement spike step 0 on the target kernel before
claiming packet receipt: attempt `ip link set <stN> master <br>` and record
the netlink result/error, then inject one bridge-forward and one bridge-input
fixture only if the kernel accepts the enslave. If the kernel rejects an
`ARPHRD_NONE` xfrmi as a bridge port, r6 downgrades bridge capture to
chain-presence/PF-bind and nonmatching-traffic overhead, keeps routed-inet
capture available, and removes the bridge-packet receipt requirement; the
rejection is the primary barrier and bridge quarantine is defense-in-depth.

For routed xfrmi plaintext, inet `forward` is the normal path and the marked
q0 path is valid. If an operator or future component places an xfrmi in a
bridge domain, bridge `forward` sees the same ownership-keyed `iifname` and
queues it before the bridge fence. The bridge row is then quarantined and
DROP-counted; it is NEVER written to q0 because q0 is `IFF_TUN` L3
(`userspace-dp/src/slowpath.rs:27-29`), not a TAP/L2 outlet. A raw ACCEPT
resumes to the bridge policy-DROP fence, so this restriction cannot reopen
bridge transit. The plan does not claim bridge permit or bridge re-entry.

xfrmi is an L3 `ARPHRD_NONE` routed device
(`userspace-dp/src/afxdp/types/forwarding.rs:708-709`,
`userspace-dp/src/afxdp/forwarding/tests.rs:4977-4983`), and SecureTunnel
exclusion is ownership-or-device-kind, never bridge-membership
(`pkg/dataplane/userspace/ingress_exclusions.go:150-158`). T12 records the
live bridge-port census and the S3 enslavement result as actuation evidence;
bridge-forward divert follows the gate and is torn down on unsafe topology.
Both family installers MUST render family-valid **forward and input**
chains/rules atomically: inet uses `ip`/`ip6` guards where applicable;
bridge's required ownership rules are `iifname`-only, and any optional L3
refinement uses `ether type` plus `ip`/`ip6` payload guards without matching
non-IP frames. The S3 enslavement result controls whether bridge packet
receipt is required as specified above.

G2 measures both fence legs plus both forward divert legs and both input
chains on non-tunnel traffic. T12 asserts that nonmatching bridge packets
continue to the bridge fence; if S3 enslavement accepts, xfrmi bridge-forward
and bridge-input packets are captured then DROP-counted (never q0-reinjected)
and their PF binds/parser provenance agree. If enslavement rejects, T12 asserts
the recorded rejection plus chain/PF-bind presence and nonmatching-traffic
behavior, with no synthetic packet-receipt requirement. No required
family/hook can be committed with only one divert-table generation.

---

## 3. S4.5 re-entry choice DECISION: reuse the #10391 marked-queue pattern

### 3.1 Decision (one line)

**DECISION: reuse the shipped #10391 marked-queue outlet (`xpf-usp1` queue zero
→ TC mark → fence conjunction) as the SOLE REINJECT re-entry path for the
single **routed inet** forwarding domain that this outlet serves, constrained
to one concrete **main-table, non-VRF/non-policy-routed, non-enslaved**
singleton. No new TUNs. No new fence pinholes. No VRF/policy-routing re-entry
topology. Captures whose adjudicated route-domain is not that main-table
singleton are DROP-and-count, never silently sent through the wrong FIB.
Bridge-family FORWARD **and INPUT** capture is quarantine-only: it is captured
and DROP-counted, never sent to q0, because q0 is an L3 TUN and cannot
preserve L2 bridge semantics (`userspace-dp/src/slowpath.rs:27-29`).**

**VRF/FIB admission constraint (PROPOSAL; S3/S4 must pin):** the concrete
`D_usp1` identity is resolved to `(main-table identity, route table, policy-rule/
mark state, l3mdev-master-or-not)` before any tunnel admission. V1 is coherent
only when the selected singleton is the **main table** and the daemon-owned
`xpf-usp1` outlet is unenslaved: a masterless q0 ingress has no rule that
steers it elsewhere and follows the main-table fallback (including pref
32766). Any non-main identity—VRF by enslavement, VRF/policy-rule selection,
or another route table—is refused. fwmark→table steering is deliberately
excluded because it would reintroduce the §4 no-VRF/policy-routing topology
prohibition. If `D_usp1` is a real VRF or other non-main identity, the
supported q0 scope is refused; the owner must choose a main-table concrete
outlet domain or authorize a separately reviewed VRF-aware re-entry/capture
plan. “D_usp1 is a VRF” is not a bypass exception.

### 3.2 Mechanism of the chosen path (every step cited)

1. Worker adjudicates PERMIT-with-mutation (NAT rewrite, the 20% REINJECT mix
   in T22) on the owned-frame path (r5 §4.4 retained). The held original stays
   queued; NOTHING is emitted yet (commit table, §8).
   Before adjudication, the worker accepts only a packet whose validated
   `CaptureOrigin` is the provenance tuple
   `{family,hook,owner,stN,owned_ifindex}` from the queue handle; any tuple or
   metadata mismatch is DROP-and-count (§2.2,
   `pkg/nfqueue/nfqueue.go:315-343,620-673`).
2. Worker publishes the completed L3 frame bytes to the adjudicated outlet via
   `SlowPathReinjector::enqueue_adjudicated`
   (`userspace-dp/src/slowpath.rs:974-985`), which tags
   `PacketQueue::Adjudicated` on the shared `tx_delegated` SyncSender
   (`userspace-dp/src/slowpath.rs:978-984`). This is QUEUE ADMISSION, NOT the
   REINJECT COMMIT: current `enqueue_on` returns `Accepted` immediately after
   `tx.try_send` (`userspace-dp/src/slowpath.rs:1000-1006,1037-1040`), while
   the sole worker later selects the q0 descriptor and executes the TUN write
   (`userspace-dp/src/slowpath.rs:1158-1179`). Depth `DEFAULT_QUEUE_DEPTH =
   16384` (`userspace-dp/src/slowpath.rs:23`), rate limits 1M pps / 4 GiB/s
   (`userspace-dp/src/slowpath.rs:24-25`). Enqueue refuses MTU-exceeding
   frames with `EnqueueOutcome::MtuExceeded` against the LIVE TUN MTU
   (degraded-aware, `userspace-dp/src/slowpath.rs:99-108`, `:1006-1013`),
   queue-full with `QueueFull`, rate-limited with `RateLimited` — all
   no-write failures are fail-closed and counted
   (`userspace-dp/src/slowpath.rs:68-97`).
3. The sole adjudicated writer drains `tx_delegated` adjudicated-tagged
   requests to file descriptor(s) of queue zero of the `IFF_MULTI_QUEUE` L3 TUN
   `xpf-usp1` (queue-index discipline,
   `userspace-dp/src/slowpath.rs:27-38`). **Single-writer rule (new S4
   invariant): exactly one fd set owns q0 writes; 9506 workers NEVER open q0
   directly — they enqueue through `enqueue_adjudicated`.** Violations are
   compile-time (no q0 fd handle outside the slowpath worker) + T2-pinned
   (one-writer-per-outlet granularity, refining r5's one-writer-per-TUN).
   Each admitted request carries an epoch-tagged completion token (PROPOSAL):
   the q0 writer completes that token only after the actual write outcome is
   definitive. S4 MUST NOT treat channel admission as terminal authorization,
   and MUST reject bridge-forward **and bridge-input** rows before this q0 path.
   **q0 `ReinjectLease` protocol (PROPOSAL; S4 owns; distinct from the r5
   emission-gate DROP lease):** the NFQUEUE adjudication worker creates a
   `ReinjectLease` containing `(permit_epoch, queue_epoch, request_id)`
   and transfers that token with the channel descriptor; it does not hold the
   q0 commit mutex across `try_send`. The sole q0 writer becomes the lease
   holder on dequeue, rechecks permit/queue epoch immediately before the TUN
   write, and holds the lease through definitive write outcome plus completion
   ACK. Permit revocation first marks queued leases canceled and **globally
   closes permit authority pending the control ACK**, then waits only for
   already-started lease holders for `T_cancel ≤ 5ms` (inside the 50ms close
   budget). A canceled/stale descriptor receives one terminal DROP and cannot
   write. If cancellation or that ACK times out, the outcome is **uncertain**:
   the permit remains closed, no reopen or retry is allowed, the already-started
   holder drains only to the retained cutoff, and S4 terminates the writer/
   helper under that cutoff so held originals fail closed. This prevents
   release-at-admission from racing revocation without making revocation wait
   on the whole channel.
   **Go→Rust epoch/cancel propagation (PROPOSAL; S4 owns):** the Go
   NFQUEUE/gate side extends `ConfigSnapshot` with `permit_epoch` and the
   per-handle `queue_epoch`; the existing `ControlRequest{Type:
   "apply_snapshot", Snapshot: ...}` family carries both to Rust
   (`pkg/dataplane/userspace/protocol.go:461-472,542-545`,
   `userspace-dp/src/server/handlers/mod.rs:262-279`). The epoch staleness
   bound is `T_snapshot_apply`, the hard request-to-helper-ACK plus
   snapshot-publication bound, and MUST be pinned at `≤50ms` for an OPEN
   transition; until that ACK the Rust writer treats the prior permit as
   closing and cannot OPEN a newer one. Lease cancellation uses a same-family
   partial-update control request (the existing
   `update_neighbors`/`update_fabrics` outcome-and-resample discipline at
   `pkg/dataplane/userspace/partial_update_outcome_9684.go:9-50`,
   `userspace-dp/src/server/handlers/mod.rs:293-345`) carrying
   `ReinjectCancel{request_id,permit_epoch,queue_epoch}`. Its hard bound is
   `T_cancel ≤ 5ms`; a lost response is not proof of either applied or
   unapplied state, so the permit stays globally closed, no descriptor
   reopens, and the retained cutoff/holder drain/termination path resolves
   held originals fail-closed. T8/T10 pin both lost-response cases (cancel
   applied versus not applied), the timeout, and exactly-once terminal
   accounting.
4. Kernel sets `skb->queue_mapping = ADJUDICATED_QUEUE_INDEX + 1 = 1` for q0
   frames (`userspace-dp/src/slowpath.rs:31-35`). The TC ingress clsact
   classifier (`ADJUDICATED_TC_PRIORITY 0x7fff`,
   `userspace-dp/src/slowpath.rs:38`), installed by
   `install_queue_mark_classifier` (`userspace-dp/src/slowpath.rs:257-318`)
   with program `load_queue_mark_program` (`userspace-dp/src/slowpath.rs:168-255`),
   FIRST clears `skb->mark` (bytes at `__sk_buff` offset 8), THEN sets
   `0x58465001` IFF `queue_mapping == 1`
   (`userspace-dp/src/slowpath.rs:168-173`, BPF insns `:173-231`). Every other
   mapping (q1 delegated, unknown) is explicitly cleared to zero and hits the
   fence DROP policy.
5. The marked frame re-enters the forward hook with `iifname == xpf-usp1`,
   `mark == 0x58465001/0xffffffff`. The fence marked-pinhole rule
   (`iifname + mark → ACCEPT`,
   `pkg/nftables/transit_barrier.go:190-193`, emitted for each
   `ForwardFenceMark` at `:181-194`) ACCEPTs it; the daemon resolves exactly
   one such mark (`pkg/daemon/daemon_transit_gate.go:159-168`,
   `pkg/daemon/transit_fence_10302_test.go:57-66`). Unmarked `xpf-usp1` frames
   (delegated q1) meet the DROP policy — the kernel holds NO accept for them
   (`pkg/nftables/host_inbound_reinject_9637.go:19-29`).
6. Userspace does NOT issue DROP on the held original at channel admission.
   For a request rejected before a q0 write (`MtuExceeded`, `QueueFull`,
   `RateLimited`, disconnected worker), userspace issues a terminal DROP on
   the original and records the no-write refusal. For an admitted request, the
   q0 writer sends an epoch-tagged completion acknowledgement (PROPOSAL) only
   after the actual `write_packet_with_mode` path returns a definitive
   successful full-frame write (`userspace-dp/src/slowpath.rs:1158-1179`;
   write-outcome distinctions at `:1184-1198` and
   `:1236-1290`). **Successful q0 TUN submission is the REINJECT commit
   point.** Only then does the capture worker issue DROP on the held original
   as cleanup under the retained r5 per-queue emission-gate **DROP lease**
   (distinct from the q0 `ReinjectLease`). A crash after the successful
   q0 write and before original-DROP yields at-most-once (replacement emitted
   once; original remains held and is dropped on queue destruction).
   A definitive no-write failure drops the original. An ambiguous or
   transferred write is `possibly-emitted`, never retried, and never followed
   by a late ACCEPT; the supervisor closes authority and reconciles only
   packets still held (terminal rule,
   `pkg/nfqueue/nfqueue.go:67-70`, `:345-381`). Completion-ack timeout is
   treated as uncertain, not as enqueue success.
   **ACK wait discipline (PROPOSAL; T8/T10 must pin):** the capture worker
   records the token in an asynchronous completion table and waits without
   holding the NFQUEUE queue mutex or the q0 writer lease. The per-request ACK
   deadline is `T_ack ≤ 5ms` (inside the retained
   `T_tick≤5ms`/50ms/70ms supervisor budget); at timeout the request becomes
   uncertain, its flow/permit epoch is closed, and no retry or late ACCEPT is
   permitted. One aggregate live-descriptor budget
   `N_live = DEFAULT_QUEUE_DEPTH = 16384` (`userspace-dp/src/slowpath.rs:23`)
   covers descriptors still queued in the channel **plus** dequeued,
   WRITE_STARTED, and unacknowledged completion-table entries; admission
   reserves that slot before `try_send`, and release occurs only at terminal
   ACK/DROP/uncertain resolution. It is not 16384 per state, so queued plus
   unacknowledged requests cannot reach 32768. Per-flow FIFO does not let later
   frames bypass a missing ACK: subsequent frames wait behind the flow's
   unresolved token, while other flows may progress. Permit revocation waits
   for `WRITE_STARTED` holders for no longer than the same ACK/write deadline;
   after that bound the holder is uncertain, authority is closed, and no late
   ACCEPT/retry is allowed. T8/T10 inject a delayed/Deferred write and assert
   the aggregate bound, timeout, bounded revocation, no-HOL-across-flows, and
   supervisor accounting.
7. TTL +1 compensation pre-enqueue, DSCP preserved in-band, GRO/GSO
   refused-and-counted, TUN-MTU fail-closed (r5 §4.5/§6.8 retained; MTU refusal
   now via `MtuExceeded`, not silent kernel drop). ICMP errors post-reinject
   reference the re-injected frame (r5 acceptable-behavior retained).
   Conntrack sees a fresh flow on `xpf-usp1` (§3.4 residual).

### 3.3a Routing-domain and L2-scope restriction (load-bearing, not implicit)

The current shared outlet carries packet bytes plus a queue-class enum, not a
VRF/RG/FIB identity (`userspace-dp/src/slowpath.rs:120-123`,
`userspace-dp/src/slowpath.rs:974-998`). An L3 frame's bytes do not encode
which VRF/FIB the capture worker used. Capture family/hook/owner therefore
comes from the immutable queue-registry `CaptureOrigin` required in §2.2
(parser-validated against netlink metadata), never from payload inference.
Therefore the marked-queue decision does **not** claim that “per-VRF routing
decisions are carried in-frame.” 9506 supports exactly one configured
**routed inet** route-domain, `D_usp1`, for q0:

1. At adjudication, the worker resolves `(tunnel, snapshot generation,
   route-domain, hook-family)` from the validated `CaptureOrigin` plus current
   snapshot and checks that the selected domain is the concrete **main-table**
   `D_usp1` identity and the hook family is inet. The owner MUST write that
   main-table identity (and the no-l3mdev-master/no-non-main-policy condition)
   into S12.5 item 6 before S4.5 item-6 Y is valid; “owner maps this later” is
   not authorization.
2. The D_usp1 overlap universe is the effective, normalized inner
   destination/source prefix set from the committed D_usp1 FIB's stN-owned
   remote/inner route prefixes plus explicitly bound inner addresses, for both
   families; outer peers/endpoints and traffic-selector text are excluded.
   Selectors remain commit-validation inputs only, never runtime policy or the
   overlap universe; broad `0.0.0.0/0`/`::/0` selectors therefore do not
   overlap by themselves when their stN-owned FIB route sets are disjoint. S4
   computes canonical intervals at admission and refreshes them on tunnel
   add/remove, stN-owned route or inner-address change, and every domain
   snapshot-generation change before OPEN. Any intersection is refused and
   counted as `nfq_reentry_overlapping_domain_total`; it is not resolved by
   FIB longest-prefix order.
3. If the decision is in `D_usp1` and the capture is inet routed transit, the
   worker may enqueue q0 and the q0 completion ack/commit path above applies.
4. T2-D_usp1 (the overlap cell) admits disjoint v4/v6 fixtures, mutates an
   stN-owned inner route/address to overlap an already admitted tunnel, and
   asserts refresh-time refusal plus unchanged prior admission; it also
   exercises a default route whose stN-owned intervals remain disjoint from a
   peer's. The T22 8/16/32 real-SA workloads MUST use pairwise-disjoint
   normalized stN-owned inner route/address sets; broad selectors are allowed
   when those FIB sets are disjoint. An overlapping route set is
   non-admissible and cannot claim T22 compliance.
   This extends T2's existing egress/TTL/policy observation with an
   **oracle pin** that the observed table is main (including the
   pref-32766 fallback); it is not a request for new instrumentation.

5. If the decision is in any non-main VRF/RG/FIB, is selected by a non-main
   policy rule/mark, the domain cannot be resolved at commit, or the captured
   packet is bridge-family FORWARD traffic, the worker issues DROP-and-count on
   the held original (`nfq_reentry_unsupported_domain_total` or
   `nfq_reentry_l2_unsupported_total`), never q0-enqueues it. This is the
   explicit supported-scope boundary, not a route leak and not a claim that an
   L3 TUN can reinject an L2 bridge frame. The q0 writer revalidates the
   selected main-table domain and snapshot generation immediately before
   acquiring the `ReinjectLease` and writing; a changed FIB/domain or a
   non-main egress identity is DROP-and-count, never a stale-snapshot q0
   permit.
6. T2 observes the actual egress interface, TTL, **egress route-table identity**
   (must be main, including pref-32766 fallback), and policy consequence for
   `D_usp1`; the wire-observed egress-table result subsumes operator-PBR
   steering/config inventory, so a configuration that claims main while the
   packet leaves through another table still fails. A route mismatch follows
   r5 detect-some-and-drop. No stronger multi-domain or bridge-L2 guarantee is
   made.

Owner sign-off item 6 MUST approve this singleton-domain/routed-inet scope
**and its main-table/no-VRF precondition**. If the owner requires all admitted
VRF/RG domains, a single VRF `D_usp1` identity, any non-main policy/table
selection, or bridge-forward permit, this decision is invalid: option C (real
per-domain TUN/VRF/policy-routing) or a separately designed TAP/L2 outlet must
be reopened; implementation may not silently widen or reinterpret the marked
outlet.

### 3.3 Why marked-queue wins (mechanism-level, not preference-level)

- **Shipped + pinned beats proposed.** The queue→TC→mark→fence chain is live
  code with LE-golden mark bytes
  (`pkg/nftables/transit_barrier_9852_test.go:184-193`), fence-spec tests
  (`pkg/daemon/transit_fence_10302_test.go:54-68`), and TC attach/detach
  lifecycle (`userspace-dp/src/slowpath.rs:136-154`, `:257-318`). r5's TUNs are
  CONFIRMED-UNBUILT (delta C40); `TunSink` is explicitly measurement-only with
  NO generation/mark/route/policy semantics
  (`pkg/nfqueue/tunsink.go:11-15`). Choosing A replaces a design-proof burden
  with an integration-proof burden (strictly smaller).
- **Zero new ACCEPT surface.** The fence marked pinhole already exists and is
  already the narrowest possible conjunction (interface AND exact full-mask
  mark). New TUNs (option B) each need a new pinhole (new bypass surface per
  TUN, each T12-pinned); VRF (option C) needs per-VRF hook/zone proofs with no
  shipped precedent (delta C44). A adds no rule to the fence table at all.
- **Provenance is structural, not configured.** Queue index is chosen by WHICH
  fd the bytes traverse, TC sets the mark, userspace cannot spoof
  `queue_mapping` through the delegated API
  (`userspace-dp/src/slowpath.rs:974-977`). VRF/policy-routing provenance is
  configured (route tables, rules, zones) and misconfigurable; per-TUN-iifname
  provenance is spoofable by any writer that opens the TUN. Structural beats
  configured for a load-bearing permit.
- **Scale bound collapses favorably.** r5's `W × I ≤ 128` (admitted workers ×
  distinct re-entry instances) assumed per-(worker,instance) TUNs. Under A
  there is ONE adjudicated outlet (q0) fed by a bounded channel; the bound
  becomes channel depth (16384) + rate limits + per-tunnel NFQUEUE fairness
  (r5 §4.2 retained), all already-instrumented
  (`SlowPathStatus`, `QueueStats` at `pkg/nfqueue/nfqueue.go:118-129`). No
  `W×I` TUN-device explosion, no per-TUN MTU/status/fd lifecycle, no
  refused-dataplane index churn for new devices (usp0/1 are helper-created,
  never in the shim ingress map, delta C41).
- **Backpressure and MTU are already fail-closed.** `MtuExceeded`/`QueueFull`/
  `RateLimited` + `live_mtu` degraded reporting
  (`userspace-dp/src/slowpath.rs:99-108`, `:68-97`) are exactly the r5
  TUN-MTU/saturation contract, already implemented. New TUNs would reimplement
  all three per device.

### 3.4 Rejected alternatives with falsifiers (what would revive them)

**Option B (REJECTED): new TUNs + new pinholes (r5 §4.5 as written).**
Mechanism: one TUN per (worker, routing-instance), `W×I≤128`, each TUN a new
fence `iifname` (or `iifname+mark`) ACCEPT + refused-dataplane listing + never
in shim ingress map. Rejected because: (i) every new pinhole widens the armed
ACCEPT surface and multiplies T12's exact-rule-set pin; (ii) per-TUN fd/MTU/
status lifecycle × up to 128 devices vs one shared outlet; (iii) no shipped
precedent (TunSink is measurement-only); (iv) identical security property
(structural provenance) at strictly higher code+test cost. **Falsifier
(revive B):** S4 measures shared-q0 TUN-stage throughput below the T22
20%-of-line-rate floor under the §8 workload AND measures sharded TUNs above
it on the same box same-day, with all other stages held constant. That result
only authorizes an Option-B proposal in a newly authorized re-plan, with the
per-TUN pinhole budget (≤N pinholes, T12-pinned) and per-TUN refused+fence
treatment subjected to the same hostile review; it never silently revives B.
Absent that measurement and re-plan, B stays rejected.

**Option C (REJECTED): VRF/policy-routing re-entry topology (r5 §4.5
topology/VRF-or-DROP arm).** Mechanism: dedicated re-entry instance per admitted
VRF/RG, policy-routing carries the captured forwarding decision, explicit
hook+conntrack/NAT-zone inventory per instance, hard no-main-transit rule.
Rejected because: (i) highest proof burden on master (no re-entry inventory
exists; the BPF conntrack publisher is a map-mirror side effect, not a q0
device/route inventory: `userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs:8-18,138-150`,
delta C44); (ii) configured-provenance risk (a VRF route leak to main is a
silent permit; a TC-mark failure is a loud DROP);
(iii) the #10391 mark-based isolation precedent achieves owned-egress with one
already-pinned conjunction, obsoleting instance-per-VRF for the isolation half
(delta item 6). **Falsifier (revive C):** owner requires namespace-grade domain
separation stronger than skb-mark (regulatory/compliance boundary), OR S4
proves shared-`xpf-usp1` conntrack zone cannot isolate adjudicated from
delegated (label/key collision: a
conntrack-entry confusion between a q0 and q1 flow with identical tuple that
survives the mark/iifname conjunction). Then C returns as a B+C hybrid (per-VRF
TUNs inside VRFs with per-VRF marked pinholes). Absent that, C stays rejected.

### 3.5 New S4 must-prove list (replaces r5 §12.4 S4 re-entry bullet)

1. Single-writer enforcement on q0 (compile-time + T2 pin).
2. Adjudicated-vs-delegated coupling: `enqueue_adjudicated` and
   `enqueue_delegated` share `tx_delegated`+`status_delegated`
   (`userspace-dp/src/slowpath.rs:978-998`) **and** one `RateLimiter`
   (`userspace-dp/src/slowpath.rs:755-758`; all classes pass through
   `enqueue_on` at `:1000-1036`). S4 MUST split sender/status **and** limiter
   buckets per class, or prove in a falsifiable G1/T8 cell that a sustained
   delegated flood at the configured limiter ceiling, while adjudicated offers
   the T22 20% REINJECT rate, leaves q0 refusal due to sender/status/limiter
   coupling within the predeclared overload-shed budget. Unproven coupling
   ⇒ DROP-and-count the coupled class, not silent cross-class loss.
3. Per-tunnel fairness THROUGH the shared outlet: per-tunnel NFQUEUE capture
   (r5 §4.2) + batches-per-poll-cycle fairness bound (r5 §4.4) + sparse
   tunnel×owner occupancy rows (r5 §8) MUST extend to q0 enqueue (new G1 row:
   per-tunnel q0 admitted/refused with all tunnels saturated).
4. Conntrack/NAT-zone and route-guard inventory for the SHARED `xpf-usp1`
   device (not per-VRF): S4 inventories every applicable netfilter hook,
   conntrack/NAT zone, strict-RPF/martian behavior, `accept_local` and related
   forwarding posture sysctls (`pkg/daemon/daemon_run_bringup.go:670-678`), and
   asserts no FIB/rule routes traffic INTO `xpf-usp1` because the q0 path only
   writes the TUN (`userspace-dp/src/slowpath.rs:1158-1179`) and has no read
   drain. On dequeue the q0 writer acquires the `ReinjectLease`; while holding
   it, the writer revalidates the selected `D_usp1` domain and snapshot
   generation immediately before writing. A changed FIB/domain is
   DROP-and-count. Unproven hook/zone/route guard ⇒ DROP-and-count.
4a. Capture provenance is a must-prove API invariant: the queue registry
    attaches immutable `{family, hook, owner, stN, owned_ifindex}` `CaptureOrigin`,
    and the parser preserves `nfgen_family`, `NFQA_PACKET_HDR.hook`, and
    `NFQA_IFINDEX_INDEV` before handing a packet to S4. For inet, the allowed PF
    set is `{AF_INET, AF_INET6}` normalized to logical `inet`; bridge allows only
    `AF_BRIDGE`. A mismatch between any netlink field and the registry handle
    is DROP-and-count, never q0. The four queue handles per tunnel
    (`inet/forward`, `inet/input`, `bridge/forward`, `bridge/input`) are
    included in allocator reuse quarantine, rotation generation, fairness, and
    occupancy accounting. Inet PF-bind failure is tunnel-DOWN; bridge handles
    MUST PF-bind `AF_BRIDGE`/`NFPROTO_BRIDGE` only when S3 has proven
    enslavement and selected the bridge capture leg. A supported bridge-leg
    bind failure is then tunnel-DOWN; an unsupported/rejected bridge leg is
    the explicit degraded fence/quarantine/chain-presence mode, not tunnel
    DOWN (`pkg/nfqueue/nfqueue.go:192-202,315-343,620-673`,
    `pkg/nftables/transit_barrier.go:39-43`).
    S4 MUST prove both bridge listeners receive actual bridge packets only when
    step 0 accepts; otherwise T12 proves the rejection, chain/PF-bind presence,
    nonmatching behavior, and no receipt claim. T12 must inject device
    delete/recreate/name-reuse with a changed ifindex and assert DROP-and-count.
5. Owned-egress and commit authority: inet-routed re-entry MUST complete an
   epoch-tagged q0 writer acknowledgement after the full-frame TUN write
   before the held original receives DROP; channel `Accepted` is not a
   commit (`userspace-dp/src/slowpath.rs:1037-1040,1158-1179`). The q0 writer,
   not the adjudication worker, owns a `ReinjectLease` descriptor from channel
   dequeue through the final write and ACK; the worker transfers the lease
   token with the descriptor and never releases commit authority at admission.
   Permit-epoch revocation cancels queued descriptors and blocks a writer whose
   permit check fails; an already-started writer is the sole bounded holder
   revocation drains before closing. The re-entered frame MUST egress with
   `iif == xpf-usp1` + mark intact to the inet fence; T2 observes egress
   interface + TTL + policy path. Ambiguous completion is possibly-emitted and
   never retried.
6. Domain/L2/VRF refusal is explicit: only the singleton routed-inet `D_usp1`
   may q0-reinject; the owner MUST name its concrete **main-table route
   identity** and whether it is an l3mdev master before S4.5 item-6 Y is valid
   (an undefined or non-main singleton is not sign-off). The admission
   precondition is that no admitted xfrmi is VRF-enslaved, including to
   `D_usp1`; if that singleton is a real VRF master, this V1 scope is refused
   unless a separate VRF-aware input/provenance re-plan is authorized. At
   admission, S4 rejects overlapping inner prefixes/addresses among all
   tunnels assigned to that concrete domain; at commit it revalidates the
   domain/snapshot before the q0 lease/write. Any other VRF/RG/FIB, any
   VRF-enslaved xfrmi, and every bridge-forward or bridge-input capture
   receives DROP-and-count (`nfq_reentry_unsupported_domain_total` or
   `nfq_reentry_l2_unsupported_total`), never a q0 write
   (`userspace-dp/src/slowpath.rs:27-29,120-123`).
7. `W×I≤128` is RETIRED as a TUN-device bound (no new TUNs); the live bounds
   are channel depth + rate limits + per-tunnel queue fairness + 32-tunnel
   admission max (r5 §4.2 retained). S7 re-prices R_tun as the shared-outlet
   term (one TUN buffer + one TC program + channel slabs), not `W×I` devices.
8. Host-input policy source is a must-prove: S4 names the tunnel-zone
   derivation and the existing `inet xpf_hostinbound` table's service-accept /
   catch-all-default-DROP disposition before enqueue. Tunnel→zone derivation
   remains **PROPOSAL/S4-owned**; S4 proves it against the canonical
   interface/address snapshot and effective per-interface-or-zone tokens
   (`pkg/dataplane/userspace/zones_host_inbound.go:165-207,208-233`). Current
   daemon rendering feeds `xpf_hostinbound`; the real netlink enforcement path
   supplies explicit default-deny, address scoping, service verdicts, and
   input-priority ordering
   (`pkg/daemon/daemon_nft.go:521-545,558-582`,
   `pkg/nftables/netlink_hostinbound.go:27-78`,
   `pkg/nftables/netlink_hostinbound_ingress_9637.go:31-52`). T5 proves host-bound
   permit/deny, mutated-host-bound DROP, and gate-closed DROP. T5's live VRF
   refusal subcell enslaves a test stN to a test VRF, proves admission/census
   refusal, records the attach-to-close pre-window status-quo host-inbound
   verdict, and proves the post-close master/default-deny fence DROP; its
   routed FORWARD companion remains the normal inet divert/fence path rather
   than an INPUT bypass.

---

## 4. S4.7 NOT proposed (r6 revision — prohibition struck)

~~No unconditional armed DROP chain (only the pinned divert rule set).~~
**r6: STRUCK — the armed fence EXISTS and is the load-bearing DROP.**
`pkg/nftables/transit_barrier.go:143-149` (armed fence retains DROP policy),
`pkg/daemon/daemon_transit_gate.go:385-389` (never removed while opening).

r6 prohibitions (authoritative):

- No SECOND armed DROP chain beyond the fence; no divert-table DROP/ACCEPT
  rules (§2.2: divert carries no verdict, drops nothing by rule; NFQUEUE
  terminal dispositions are the explicit DROP/ACCEPT API at
  `pkg/nfqueue/nfqueue.go:37-45`) — the retained half of the overtaken C23
  claim.
- No raw-ACCEPT forward permit for diverted packets (fence-closed no-op,
  §2.3 step 3; the no-xfrmi pinhole is
  `pkg/daemon/daemon_transit_gate.go:122-124`; S3 spike must prove
  resumption-to-fence).
- No new TUNs, no new fence pinholes, no VRF re-entry topology (decision §3;
  falsifiers recorded, not open alternatives).
- No AF_XDP on xfrmi (exclusion intact at
  `pkg/dataplane/userspace/ingress_exclusions.go:150-158`). No AF_PACKET
  anywhere. No userspace ESP decryption. No selector-as-policy: selectors
  are commit-validation only at
  `pkg/config/compiler_ipsec_trafficselector.go:39-65`, never a runtime
  permit.
- No SO_MARK-on-TUN claim: the only TUN sink is measurement-only and says
  the proposal is not implemented (`pkg/nfqueue/tunsink.go:11-15`), while
  the NFQUEUE package explicitly claims no mark mechanism
  (`pkg/nfqueue/nfqueue.go:14-18`). The #10391 TC queue→skb-mark is the
  separate structural path (`userspace-dp/src/slowpath.rs:974-977`), not
  SO_MARK.
- No mark-based ACCEPT except the single shipped `(xpf-usp1, 0x58465001)`
  conjunction (`pkg/nftables/transit_barrier.go:181-194`); a second
  mark-accept would be the refuted chain returning in a new spelling —
  topology/provenance, not new marks, carries every future permit.

---

## 5. S8 gates: G2/T12 fence-aware (chain-presence + expanded scope)

### 5.1 G2 (revised — fence-aware chain-presence)

> G2 — divert + verdict loop on real SAs (v4/v6, NAT-T/native ESP, routed
> inet forward+input, 8/16/32), plus bridge forward+input chain-presence and
> non-tunnel overhead: per-diverted routed-inet cost AND
> **fence+divert chain-presence overhead on non-tunnel traffic with BOTH
> tables co-installed**; bridge xfrmi packet receipt is a separate S3/T12
> unsafe-topology conformance cell, not a steady-state G2 capture claim.

Revisions vs r5 (all fence-driven):

- Baseline modes (same box, same day, loss cluster): (i) fence-alone
  (`xpf_transit_barrier` inet+bridge, armed pinholes live), (ii-a)
  fence+divert with `xpf_ipsec_divert` inet+bridge forward plus inet+bridge
  input at P_divert, exact stN rules, four provenance-specific queue handles
  per tunnel, inet PF binds, and AF_BRIDGE PF binds, but all required NFQUEUE
  listeners **detached** (no socket/listener binding), and (ii-b) the same
  fence+divert rules with all required listeners **attached and idle** (zero
  offered xfrmi load). (iii) is fence+divert+capture with an 8-tunnel
  **routed-inet** XFRM workload whose admitted stN fixtures are
  non-VRF-enslaved and have no non-main policy/table selection.
  Non-tunnel routed AND bridged forwarding is concurrent in every mode; the
  veth-pair/bridge topology with IPv4, IPv6, and non-IP frame mixes and no
  owned xfrmi membership. Inet host-bound input traffic is included in (ii-a),
  (ii-b), and (iii), while bridge-input is measured only as installed-chain/
  PF-bind and nonmatching-traffic cost (no owned `stN` bridge-input packet in
  steady state). Report `(ii-a)-(i)` as chain traversal, `(ii-b)-(ii-a)` as
  listener/socket/FD/buffer binding, and `(iii)-(ii-b)` as routed-inet capture.
  Bridge xfrmi packet receipt is not required in any steady-state baseline:
  the unsafe bridge-membership receipt cell is owned by S3/T12 below. Every
  routed-inet capture row also validates queue-ID →
  `{family,hook,owner,stN,owned_ifindex}` provenance before verdict; metadata
  mismatch is a DROP-and-count row.
- **Mandatory live-VRF refusal overhead cell (G2; V1 is inet INPUT only):**
  S3 creates a test VRF and attempts to enslave a test `stN`, then prices the
  inet INPUT twin's pre-admission refusal, census close, master/default-deny
  host fence, and DROP-only quarantine/listener overhead in the same
  fence-alone and fence+divert baselines. The cell is not a steady-state
  VRF-capture claim: it reports the pre-close status-quo host-inbound path and
  post-close fence cost separately. Bridge quarantine is VRF-immune by kernel
  construction (one `MasterIndex`; a link is a port or a slave, not both), so
  no bridge VRF-match rule is added; G2 nevertheless asserts bridge chain
  presence/nonmatching cost and the ordinary inet FORWARD slave visibility.
- Queue economics is a **MUST-price extension**, not an already-measured M2
  result: each `Queue` owns a netlink socket plus a 1 MiB userspace receive
  buffer and requests 4 MiB socket buffers
  (`pkg/nfqueue/nfqueue.go:113-115,170-189`). At the 32-tunnel admission
  maximum, the M2/G2 extension MUST price up to 128 queue/socket instances,
  128 receive buffers, socket-buffer reservations, FD limits, allocator
  capacity, rotation overlap, and teardown; the current one-queue M2 shape
  (`pkg/nfqueue/measure_memory_test.go:26-31`) is only a seed. Any cap miss is
  a T22/G2 failure, not an omitted cost.
- Provenance cost is not hidden in per-packet capture cost: the allocator,
  parser metadata preservation, AF_BRIDGE PF bind, per-hook queue listeners,
  rotation/quarantine, and fairness/occupancy accounting are reported
  separately. A run with an unvalidated shared queue is not a G2 pass.
- Bridge leg included as chain-presence/non-tunnel overhead: non-tunnel
  BRIDGED throughput/pps is measured in all three baselines (fence bridge
  leg and bridge divert leg live throughout the baseline); bridge xfrmi
  packet receipt is tested only by the unsafe-topology S3/T12 conformance
  cell, and remains quarantine/drop-count-only with no q0 re-entry claim.
- Kill phrasing UNCHANGED in polarity, widened in scope: if the B-invariant
  portion (capture→worker wake excluded; socket half + fence+divert residual
  traversal) alone busts T22, no B saves it. The verdict-API shape priced is
  the Phase-0-selected per-packet sendmmsg batching
  (`pkg/nfqueue/nfqueue.go:390-466` `VerdictBatch`; `nfqnlMsgVerdictBatch=3`
  const at `:82` unused by the batch path — no kernel cumulative semantics,
  delta C12). Mixed batches use per-packet verdicts or disposition-homogeneous
  grouping where lower-ID constraints permit (r5 §2 retained).
- M1/M2 re-baselining (§8): G2's per-shape expectations are seeded from M1
  synthetic baselines (inline/B=3/B=8/affinity,
  `pkg/nfqueue/measure_stages_test.go:24-42`) and M2 memory accounting
  (`pkg/nfqueue/measure_memory_test.go:26-31`), but the KILL gates remain
  loss-cluster T22 measurements, never synthetic promotions.

### 5.2 T12[P] (revised — fence+divert coexistence + expanded scope)

> T12[P] armed paths + `oif == stN` + exact-rule-set scope pin, integrated
> through the apply-locked/background entries into
> `reassertTransitGateLocked` under `transitGateMu`
> (`pkg/daemon/transit_gate_tick_9725.go:56-104`), with divert live.

Expanded scope cells (each fail-on-revert; `[P]` = passes TODAY with fence
alone where noted, fails until divert lands otherwise):

1. `[P]` Fence exact-shape: `xpf_transit_barrier` MUST be present on inet
   for every divert-live phase. When S3 enslavement and bridge support are
   accepted, it MUST also be present on bridge; absence then fails T12 because
   the required bridge divert cannot ship safely. A target that returns the
   documented `ErrTransitBarrierBridgeUnsupported` sentinel may take the
   explicit degraded inet-only branch (`pkg/nftables/transit_barrier.go:39-43`):
   no bridge divert/receipt claim is made, and T12 records chain/nonmatching
   evidence only. Chain `forward`/hook forward/filter priority/policy DROP
   (`pkg/nftables/transit_barrier.go:164-175`);
   pinholes EXACTLY the spec from `armedTransitFenceSpec` (tracked XDP
   unmarked + one marked `xpf-usp1`); no `xfrmi`, `leave-alone`, `unmanaged`,
   `xpf-usp0` in ANY pinhole
   (`pkg/daemon/transit_fence_10302_test.go:54-68`, extended to live ruleset
   dump).
2. Divert exact-shape: when bridge support/enslavement is accepted,
   `xpf_ipsec_divert` is present on **inet and bridge**; each family has
   `forward` and `input` chains at EXACTLY P_divert (-175). In the documented
   degraded bridge-unsupported branch, only the inet divert is a required
   packet path and T12 records bridge chain/PF-bind/nonmatching evidence
   without a receipt claim. Forward rules exactly the ownership-keyed stN set
   → each `(family,forward,stN)` queue (no ACCEPT/DROP/mark); inet input rules
   exactly `iifname == stN` → each `(inet,input,stN)` queue; supported bridge
   input rules exactly `iifname == stN` → each `(bridge,input,stN)` queue,
   quarantine-only (no q0); chain policies ACCEPT for nonmatching frames.
   Four queue handles per tunnel are provenance-specific and included in
   allocator/rotation/fairness accounting; inet handles PF-bind
   AF_INET+AF_INET6 and supported bridge handles PF-bind AF_BRIDGE. Q7 pins
   the rule set and bindings against drift (r5 §4.2 retained).
3. Coexistence ordering: on the supported two-family path, nft dump proves
   P_divert < filter on hook forward in **both inet and bridge**, and on hook
   input in **both families**, and proves no same-priority forward/input base
   chain exists in either family; fence policy DROP is intact with both divert
   families live. Divert rotation uses one cross-family netlink transaction for
   the generation and never perturbs fence handles, while fence reassert never
   perturbs divert handles. The permit-generation close is **global to the
   shared transit outlet**: per-tunnel queue retirement may not claim a
   narrower outage or leave another tunnel OPEN on an uncommitted generation.
   The per-rotation outage budget is two `T_nl` deadlines plus source-cutoff/
   drain and rollback; G2 reports duration/frequency per rotation and T12
   fails any over-budget or mixed-generation **OPEN**. If the API fallback is
   used on the supported path, T12 injects the **successful staged path**:
   after permit close, inet and bridge replacement generations are both
   installed quarantine-only; neither can OPEN until both family rules,
   listeners, PF binds, and provenance agree, then one joint activation
   publishes the generation and destroys old handles. On the degraded
   bridge-unsupported path, only the inet replacement stages/activates and
   bridge remains chain/PF-bind/nonmatching evidence with no receipt claim.
   Failure during staging removes the staged family and restores the old
   generation (or forces tunnel-DOWN if rollback fails). A mixed generation
   may exist only closed/quarantine-only, never as a mixed OPEN generation.
   Delete-before-install admits no packet; post-install arrival reaches the
   registered generation. Each received packet's queue-ID mapping,
   `nfgen_family`, `NFQA_PACKET_HDR.hook`, and `NFQA_IFINDEX_INDEV` must agree
   with its registered `{family,hook,owner,stN,owned_ifindex}` origin; a
   mismatch is DROP-and-count. T12 includes device delete/recreate/name reuse
   with a changed ifindex.
4. No-bypass proof (the §2.3 corollary, measured): with both divert families
   + all four provenance-specific queue classes + both fence families live,
   (a) leave-alone routed and bridged transit still DROPped (packet generator
   on unzoned phys, verdict = family fence DROP, divert counters unbiased);
   (b) diverted inet xfrmi packet issued ACCEPT still DROPped
   (resumption-to-fence; S3 spike cell, kill polarity); (c) marked `xpf-usp1`
   q0 re-entry ACCEPTED iff mark exact on routed inet (q1 unmarked DROPped;
   wrong-mark DROPped); (d) **only when bridge enslavement step 0 is
   accepted**, diverted bridge-forward xfrmi and bridge-input xfrmi are
   DROP-counted and NEVER q0-reinjected; when rejected, the degraded branch
   asserts chain/PF-bind/nonmatching behavior only; (e) every received
   packet's queue-ID,
   `nfgen_family`/`NFQA_PACKET_HDR.hook`/`NFQA_IFINDEX_INDEV`, and owner
   metadata matches the registered `{family,hook,owner,stN,owned_ifindex}`;
   mismatch is DROP-and-count; (f) `oif == stN` outbound untouched; (g)
   SNAT/`accept_local`/`#7409` live (citations §2.2).
5. Bridge conformance cell (**not a steady-state G2 workload**): first run
   S3 enslavement step 0 (`ip link set <stN> master <br>`) and record the
   target-kernel result. If accepted, fence bridge `forward` DROP is live;
   bridge divert `forward` and **input quarantine** chains are live at
   P_divert; each bridge queue PF-binds AF_BRIDGE. T12 uses an S3-owned,
   test-only injectable gate close-phase barrier: after the guard detects the
   bridge-master attach and revokes the permit epoch, it pauses before forward
   emission gates transition `OPEN→CLOSING`/source cutoff/teardown. While
   paused, T12 injects actual bridge-forward and bridge-input packets and
   waits for both listeners with `T_bridge_rx ≤ 5ms` per listener (S3 pins the
   bound); a timeout fails the accepted-enslavement cell rather than hanging.
   Both must report matching `nfgen_family` + `NFQA_PACKET_HDR.hook`; userspace
   issues terminal DROP-and-count for both.
   Releasing the barrier then asserts forward gate close, bridge-forward
   teardown, retained bridge-input DROP-only quarantine, and no reopen until a
   safe census and complete four-hook generation commit. If the kernel rejects
   enslavement, T12 asserts the recorded rejection, chain/PF-bind presence and
   nonmatching bridge behavior only; it does not synthesize bridge xfrmi
   packets or fail routed-inet capture. No TAP/L2 claim is made.
5a. **Live VRF/l3mdev refusal cell (V1 scope = inet INPUT twin only):**
   S3's spike MUST create a test VRF and attempt
   `ip link set <stN> master <vrf-test>`, record the `MasterIndex`/netlink
   result, and exercise the **same fixture at both hooks** through three phases.
   Before attach, inet INPUT host-bound packets hit the admitted `stN` NFQUEUE
   listener. The VRF attach first triggers the nonblocking permit CAS
   `OPEN→CLOSING`; before the fence ACK, packets receive only the bounded
   status-quo host-inbound verdict and produce zero INPUT-queue hits, and T12
   records no close/DOWN claim. After the fence ACK/read-back but before the
   conntrack ACK, packets may hit the master/default-deny DROP but close remains
   CLOSING with no post-close DROP or tunnel-DOWN claim, still producing zero
   INPUT-queue hits. Only after both fence and conntrack ACKs and close are
   committed do packets hit the authoritative master/default-deny host fence
   DROP and still produce zero INPUT-queue hits. The fixture places an accepted
   service on the shared master and asserts the fence-anyway choice: it is also
   DROP-counted and emits the CRITICAL shared-master alarm/evidence row. T12
   injects `InstallHostInbound` failure, ACK timeout/read-back mismatch, fallback
   default-deny failure, and conntrack-revocation failure, requiring
   retry/reassert, `conntrack_fence_debt`, stuck-DOWN/no-reopen, and no
   post-close DROP claim until a later fence+conntrack ACK. While the barrier is
   paused, T12 runs a normal config apply through `applyHostInboundFilter` and
   keeps an established/related session on the shared master; the apply must
   merge the active overlay, not erase an ACKed deny, and revocation must
   terminate the session. At inet FORWARD, packets continue
   to hit the ordinary slave-visible stN divert/fence path until intentional
   gate teardown, then are fence-DROPped; no INPUT bypass or VRF-master
   capture is claimed. G2 prices the inet INPUT chain/listener/fence overhead
   for this live cell, including pre-close status-quo and post-close DROP
   separately. Bridge is deliberately outside the VRF fix: its quarantine is
   VRF-immune by kernel construction (single `MasterIndex`, port XOR slave), so
   T12 asserts bridge chain presence/nonmatching quarantine without adding a VRF
   match or requiring bridge packet receipt.
6. Integration: divert install/rotation/teardown ONLY via gate helpers under
   `transitGateMu`; bare nft writers fail the test (r5 §12.4 S3 retained).
   Inet divert install/PF-bind failure ⇒ tunnel DOWN. Bridge divert install or
   PF-bind failure ⇒ tunnel DOWN only when S3 enslavement step 0 accepted and
   the bridge leg is required; an unsupported/rejected bridge leg follows
   `ErrTransitBarrierBridgeUnsupported` degraded fence/quarantine/
   chain-presence/nonmatching proof, retains routed-inet capture, and makes no
   bridge packet-receipt claim.

Q7 scope-sufficiency is now OPEN-harder (delta C55): T12 as expanded above is
the sufficiency argument (two writers, both-family FORWARD hooks plus inet
and bridge INPUT (bridge quarantine), bridge+inet, queue/PF/provenance
bindings). If
hostile review finds a coexistence interleaving T12 does not pin, S3 owns the
new cell (not a plan edit).

---

## 6. S12.5 items 5–6 re-sign drafts (exact Y/N text for the owner)

r5 items 1, 2, 3, 4a–4d, 7 HOLD (delta: 1 reconfirm cheaply with #7437 freshness
noted; 2 untouched; 3 with G2 chain-presence now including the fence table per
§5.1; 4a–4d no supervisor on master; 7 strengthened — implemented at
`pkg/nfqueue/nfqueue.go:345-381`, `:390-466`, `:67-70`). Items 5–6 NEED RE-SIGN:
#10391 shipped a mark-based alternative the sign-offs did not contemplate
(delta). Draft replacement text (owner answers Y/N to each as written):

> **5. Re-entry metadata (Y/N) — RE-SIGNED for marked-queue + write ACK.**
> Do you approve STRUCTURAL QUEUE PROVENANCE — `xpf-usp1` queue zero via
> `enqueue_adjudicated` (`userspace-dp/src/slowpath.rs:974-985`), TC-ingress
> mark `0x58465001` IFF `queue_mapping == 1`
> (`userspace-dp/src/slowpath.rs:168-173`), admitted ONLY through the shipped
> fence `(xpf-usp1, exact-mark)` conjunction
> (`pkg/nftables/transit_barrier.go:181-194`) — as the SO_MARK replacement for
> 9506 REINJECT, INSTEAD OF topology/VRF plus policy-routing? Every capture
> verdict is preceded by validated `{family,hook,owner,stN,owned_ifindex}`
> provenance from the queue handle and preserved `nfgen_family`,
> `NFQA_PACKET_HDR.hook`, and `NFQA_IFINDEX_INDEV` metadata
> (`pkg/nfqueue/nfqueue.go:192-202,315-343,620-673`); inet accepts
> `{AF_INET,AF_INET6}` as logical `inet`, bridge accepts only `AF_BRIDGE`.
> A metadata, ifindex, or name-reuse mismatch is DROP-and-count and never q0;
> bridge-forward **or bridge-input** rows never enter q0 (§2.2/T12). This
> sign-off also requires the admission precondition that no admitted xfrmi is
> enslaved to an l3mdev VRF master; S3 must prove the census refusal and the
> ACKed post-detection host-input fence publication (including runtime
> shared-master fence-anyway/alarm evidence) rather than infer xfrmi provenance
> from the substituted master name.
> `Accepted` from the bounded channel is not terminal; the q0 writer owns the
> transferred `ReinjectLease` through the full-frame TUN write and
> epoch-tagged completion ACK (`userspace-dp/src/slowpath.rs:1037-1040,1158-1179`).
> Permit revocation cancels queued leases and stale ACCEPT becomes exactly one
> DROP; the ACK wait is asynchronous with `T_ack≤5ms`, bounded by channel depth,
> and a timeout is uncertain/no-retry under §3.2. Only that successful write
> commits REINJECT; no-write/ambiguous outcomes are DROP-and-count /
> possibly-emitted-never-retried under §3.2. Cases the shared outlet cannot
> express (MTU-exceeded against live TUN MTU, queue-full, rate-limited;
> `EnqueueOutcome`, `userspace-dp/src/slowpath.rs:68-108`) are explicitly
> DROP-and-count, never silent permits. Single-writer on q0 (no direct 9506
> opens) and the coupling/limiter proof-or-split (§3.5 item 2) are S4
> must-proves under this sign-off.

> **6. Topology (Y/N) — RE-SIGNED for shared routed-inet outlet + mark
> isolation.** Do you approve ONE SHARED ADJUDICATED OUTLET (single
> `xpf-usp1` queue zero, all supported routed-inet tunnels/workers via the
> bounded channel) with MARK-BASED ISOLATION (TC-cleared default + exact fence
> conjunction) INSTEAD OF one dedicated re-entry instance per admitted VRF/RG
> routing domain with explicit conntrack/NAT zones per instance and a hard
> no-main-instance-transit rule? This sign-off explicitly limits 9506 q0 to
> one configured routed-inet domain `D_usp1`, whose concrete **main-table**
> identity MUST be written into this sign-off before the owner can answer Y
> (S4's undefined “owner maps this later” is not authorization). The owner
> MUST reject any non-main policy-rule/table selection and answer whether the
> concrete identity is an l3mdev VRF master. The admission precondition is:
> **no admitted xfrmi is VRF-enslaved, including to `D_usp1` itself, and the
> daemon-owned `xpf-usp1` outlet is unenslaved**. If `D_usp1` is a real VRF
> master or another non-main identity and the route-instance/policy bind would
> select it, item 6 is N for this V1; the owner must authorize a separate
> VRF-aware input/re-entry/provenance re-plan or choose a main-table outlet
> domain. The packet bytes do NOT carry a VRF/FIB identity
> (`userspace-dp/src/slowpath.rs:120-123`), so every other VRF/RG/FIB and every
> rejected VRF-enslaved capture is DROP-and-count rather than sent through an
> unproven route domain
> (`pkg/nftables/transit_barrier.go:181-194`).
> Owned-egress for `D_usp1` is enforced by the fence conjunction reaching only
> marked q0 frames and by the **main-table** egress oracle, NOT by a VRF
> boundary; the shared-device hook/conntrack inventory (§3.5 item 4) replaces
> the per-VRF inventory; and `W×I≤128` is retired as a device bound (§3.5
> item 7). A requirement for multi-domain, a single-VRF singleton, or
> bridge-forward permit revives option C (real per-domain TUN/VRF/policy-routing)
> or a separately designed TAP/L2 outlet, not an implicit widening of this
> sign-off.

Re-sign procedure: owner replies Y/N per item IN THIS THREAD (no side channel);
N/refusal on either item is a **PLAN-KILL for this r6 deliverable**, honoring
the delta memo's explicit kill criterion. Any alternative (r5 TUN/VRF choice
set, TAP/L2 bridge outlet, or a new domain mechanism) requires a separately
authorized re-plan and hostile review; it is not silently revived here. Y on
both authorizes S4 on the §3.5 must-prove list. Items 1–4/7 need no new
signature (HOLD noted above) but may be reconfirmed cheaply alongside.

## 7. Advisory wording fix (exact replacement text)

### 7.1 Required fix: `pkg/config/compiler_ipsec_plaintext_warn.go:102-104`

Current text (stale post-#10302: "still kernel-forwarded" is false for FORWARD
transit, which is now fence-dropped; "still unadjudicated" remains true —
dropped without policy; INPUT/host-bound untouched by the FORWARD fence;
delta C05b):

```go
// the INGRESS half — the plaintext the kernel XFRM stack delivers ON the
// xfrmi, which is still kernel-forwarded and still unadjudicated (#9506 owns
// that half; the exclusion above is what makes it so). It is NOT about the
```

EXACT REPLACEMENT (comment-only, pre/co-requisite to any S3 divert landing;
S3 owns the commit):

```go
// the INGRESS half — the plaintext the kernel XFRM stack delivers ON the
// xfrmi, which remains unadjudicated (#9506 owns that half; the exclusion
// above is what makes it so): FORWARD transit is fence-dropped while armed
// (#10302: policy-DROP + XDP/mark pinholes, xfrmi absent — fail-closed,
// not forwarded), and INPUT/host-bound plaintext still reaches the local
// input path without tunnel-zone policy. It is NOT about the
```
Diff intent (reviewer checklist): (i) deletes the false "kernel-forwarded"
claim for FORWARD; (ii) keeps "unadjudicated" as the load-bearing adjective
(fence-DROP applies no policy); (iii) names both residuals (fence-dropped
FORWARD + local-input-path plaintext) so a later reader cannot conclude
"fence-dropped ⇒ adjudicated"; (iv) preserves the INGRESS-vs-EGRESS scoping
(the following lines about #7949 egress adjudication are untouched).

### 7.2 Companion fix (same commit, flagged, NOT optional)

The user-visible `mechanism` string at
`pkg/config/compiler_ipsec_plaintext_warn.go:226-228` carries the same stale
"forwarded by Linux routing" claim operators actually read:

```go
mechanism: "Route-based IPsec decrypts in the kernel XFRM stack and the plaintext is " +
    "forwarded by Linux routing, which xpf does not adjudicate: no zone policy, no " +
    "session, no NAT and no screen are applied to it.",
```

EXACT REPLACEMENT (same commit as §7.1):

```go
mechanism: "Route-based IPsec decrypts in the kernel XFRM stack and the plaintext is " +
    "not adjudicated by xpf: FORWARD transit is fence-dropped while the armed " +
    "transit fence is installed, INPUT/host-bound plaintext still reaches the " +
    "local input path without tunnel-zone policy, and no session, NAT or screen " +
    "are applied to either half.",
```

The `lead` ("NOT evaluated against xpf security policies",
`:221-222`) and headings/caveat (`:193-216`, `:224-225`, `:229-231`) are
UNCHANGED — still exactly true (a fence-DROP evaluates no policy). Advisory
shape (one aggregated advisory, zoned/unzoned partition, shared renderer with
#5618 WireGuard at `:176-185`) is unchanged.

---

## 8. Retained by reference (r5 stands; re-baselines noted)

- **Commit table + terminal accounting.** r5 §4.2 commit table (ACCEPT/DROP at
  successful verdict submission under the per-queue-instance emission gate;
  REINJECT at successful nonblocking full-frame TUN write under the same gate;
  DROP-on-original as cleanup) + r5 §12.3 emission/terminality clauses +
  N7-equivalent "possibly emitted, never retried, no late ACCEPT." NOW
  CODE-BACKED (delta C24): `done` CAS + `ErrAlreadyVerdicted` +
  attempted/successful/uncertain counters at
  `pkg/nfqueue/nfqueue.go:345-381` (per-packet) and `:390-466` (batch),
  `QueueStats` at `:118-129`, `ErrClosed`/`ErrTimeout` at `:59-65`. r6
  keeps REINJECT's commit at the **successful q0 full-frame TUN write
  completion ACK**, not channel admission (`userspace-dp/src/slowpath.rs:
  1037-1040,1158-1179`; completion ACK is a required S4 extension);
  DROP-on-original remains cleanup after that commit, and lease/gate/epoch
  mechanics remain unchanged.
- **NFQUEUE transport choice.** r5 §2 factual correction retained (plan asserts
  nothing about API availability; implementation selects + prices). FIRST
  ANSWER now exists (delta C12): Phase-0 selected per-packet sendmmsg batching
  (`Queue.VerdictBatch`, `pkg/nfqueue/nfqueue.go:390-466`); `nfqnlMsgVerdictBatch=3`
  (`:82`) unused by the batch path (no kernel cumulative semantics). G2 prices
  the chosen shape (§5.1); cluster pricing remains open.
- **Shadow phasing.** r5 §4.6 retained verbatim (shadow ACCEPT-always with
  divergence counts; drain-before-activation flip with source-cutoff ack,
  finite drain set, receive-time phase tuple, cancel-beats-ACCEPT, quarantined
  shadow sessions; enforcing with same-change advisory removal). Shadow
  divergence is a policy-divergence claim only, **not predictive of q0
  admission**: shadow ACCEPT does not exercise q0 enqueue refusal, D_usp1
  overlap/domain checks, limiter coupling, lease transfer, TUN write, TC mark,
  or completion ACK. T14 therefore adds a q0 dry-run cell using synthetic
  adjudicated frames in the production netns with the write suppressed:
  admission, domain/overlap, limiter, lease/epoch and refusal counters run;
  no real packet is forwarded. The existing fence-closed shadow ACCEPT is a
  separate cell, classified as fence-closed rather than divergence because
  policy ACCEPT resumes to the armed fence and is dropped. If the owner refuses
  the dry-run, the sign-off records explicit risk acceptance that shadow does
  not soak q0 and G2/T2 remain the first enforcing q0 exercise.
  Even when the dry-run is accepted, it is not a full q0 soak: it does not
  exercise an actual TUN/TC/fence/ACK path. The owner sign-off MUST
  unconditionally record that G2/T2 is the first enforcing q0 mechanism
  exercise; refusal of that risk acceptance is a plan stop, not a silent
  shadow pass.
- **T22 shape, re-baselined on M1/M2.** r5 §8 T22 workload/mix/floors/ polarities
  retained (IMIX + jumbo; 8×4K flows bidir 60/40; 70/20/10 mix; 5% frag; 1%
  host-bound; +20% overload-shed class; 80%/250µs kill hypotheses; 90→81→80
  sanity line; 5 runs ±10%; ≤5% non-tunnel degradation; stage-rate floors).
  The 1% host-bound fixture MUST state its topology: non-VRF-enslaved xfrmis
  are the passing T22 workload, while a VRF-enslaved deployment is routed to
  the separate T5/T12/G2 live-refusal cell and cannot be counted as ordinary
  host-bound capture coverage (its INPUT path is the documented bypass/refusal
  case).
  RE-BASELINED (delta item 3): M1 synthetic transport baselines
  (`pkg/nfqueue/measure_stages_test.go:24-42`, shapes inline/B=3/B=8/affinity)
  and M2 memory accounting (`pkg/nfqueue/measure_memory_test.go:26-31`, RSS/
  cgroup/slab/Go-alloc with explicit unattributed-slab residual) seed G2
  expectations; M3 source-release pins teardown
  (`pkg/nfqueue/measure_teardown_test.go:10-79`, delta C28/C57). NO synthetic
  result promotes to a kill-gate pass; T22 still gates ONLY on loss-cluster
  real-SA measurements. G2 chain-presence now includes the fence table (§5.1).
- **Fragment contract + #9950 intersection duty.** r5 §6.8 remains the
  9506 NFQUEUE contract (v6 overlap-drop + exact-duplicate
  `(offset,end,bytes,More)` tuple + atomic/non-atomic domain split + bounded
  tombstones; v4 first-wins retained-set completion with holes⇒DROP; ≤128×64KiB
  caps; separate datagram deadline; sweep quota; hook/defrag cells on both
  paths). S6 MUST first identify the actual hook intersection with shipped
  `#9950 (F-035)`: its overlap tracker and pre/post-translation checks run on
  AF_XDP physical-ingress/TX paths
  (`userspace-dp/src/fragment_overlap/mod.rs:1-8,300-304,556-560`;
  `userspace-dp/src/afxdp/poll_descriptor/mod.rs:464-560,5180-5205`), while
  9506 xfrmi packets enter through NFQUEUE and q0 writes the kernel TUN
  (`pkg/dataplane/userspace/ingress_exclusions.go:150-158`,
  `userspace-dp/src/slowpath.rs:1158-1179`). If the hook/keyspaces are
  disjoint, S6 records a no-interaction proof with distinct counters; no
  cross-path reconciliation is required. If q0 egress is later shown to pass a
  #9950 hook, S6 names that hook and precedence, then reconciles duplicate/
  overlap accounting there. No dual-tracker claim is accepted without this
  intersection evidence.
- **S12.3 mechanism clauses.** r5 §12.3 retained verbatim (emission gate
  OPEN/CLOSING/CLOSED + shared lease + exclusive revocation; source-first
  teardown with cutoff ack + independent destruction + supervisor confirmation;
  route/re-entry detect-some-and-drop + owned-egress-via-conjunction (§3.5
  retarget); resources worksheet `R_total ≤ R_box` with packet/object/queue/
  worker/TUN caps + sweep quota + recovery; `R_tun` repriced as the shared
  outlet (§3.5 item 7); 50ms/`T_tick≤5ms`/70ms bounds unchanged (no
  supervisor on master, delta C26).
- **Skeleton + bounds + refusal rules.** r5 §2 budget derivation notes (C07/C08
  STALE-UNCERTAIN — see §9 open items), §3 shipped-work list (with C13/C17
  progress noted in §1.1), §4.3 handoff (per-flow FIFO + sole lock + fragment
  pool + owner-homogeneous sub-batches, delta C32-C35), §4.4 adjudication entry
  (owned-frame pattern live at `logical_ingress.rs:79`, IPsec entry unbuilt,
  delta C36-C39), §5 API preservation, §6 invariants (with §6.12 STALE-
  UNCERTAIN C51 and §6.13 ownership oracle CONFIRMED C52), §7 risks (R8
  retargeted to fence+divert), §9 out-of-scope (+ §4 additions), §10 open
  questions (Q3 resolved retained; Q7 harder per §5.2), §11 acceptance
  (reviewers + G1/G2 + T-suite + no struck citations), §12.1/12.2/12.4/12.6
  (disposition table, N-clauses, slice order with S3 owning §2+§7 and S4 owning
  §3, residual risks + §3.5 coupling as new risk 13).

## 9. Open questions needing owner sign-off + kill criteria

### 9.1 Open questions (each blocks its slice; answers in-thread)

1. **S12.5 items #5/#6 re-sign (Y/N)** — §6 as written. Blocks S4.
   N/refusal on either item is a PLAN-KILL for this r6 deliverable;
   alternatives require a new re-plan.
2. **S3 spike authorization (Y/N):** authorize the fence+divert coexistence
   spike FIRST: co-install fence + `xpf_ipsec_divert` at P_divert on BOTH inet
   and bridge, on forward and input hooks; instantiate the four
   provenance-specific queue classes per tunnel, PF-bind inet queues to
   AF_INET/AF_INET6 and bridge queues to AF_BRIDGE, and first run the
   bridge-enslavement step 0 (`ip link set <stN> master <br>`) on the target
   kernel, recording the netlink result/error. The same spike MUST run the
   live-VRF probe (`ip link set <stN> master <vrf-test>`), assert
   pre-admission/census refusal plus the bounded INPUT status-quo-to-fence
   transition, including a render/install/ACK publication barrier, traffic
   during publication, targeted/fallback install failure, and shared-master
   fence-anyway alarm/stuck-DOWN behavior;
   T5 owns verdicts, T12 owns capture/quarantine and both-hook race evidence,
   and G2 owns the INPUT fence/listener overhead. It MUST also assert the
   daemon-owned `xpf-usp1` outlet is unenslaved and that the selected
   `D_usp1` egress table is main. Only if bridge enslavement is accepted does
   S3 inject one bridge-forward and one bridge-input xfrmi fixture and prove
   the listener receives both; if rejected, S3 proves the recorded rejection
   plus chain/PF-bind/nonmatching-traffic behavior and does not require
   synthetic bridge packet receipt. Prove §2.3 steps 2–4 by measurement
   (leave-alone routed/bridged still dropped, inet ACCEPT resumes to fence,
   routed-inet q0 marked accepted / q1 unmarked dropped; **if bridge
   enslavement step 0 is accepted**, bridge xfrmi is captured then
   DROP-counted); parser/API provenance must report
   matching `nfgen_family` + `NFQA_PACKET_HDR.hook` + `NFQA_IFINDEX_INDEV` +
   owner queue origin, and the kill-polarity mutants must be reported. Blocks
   S1+ divert code. A "no" is a PLAN-DEFER; routed-inet capture cannot ship
   without the inet proof, while unsupported bridge enslavement follows the
   documented degraded branch rather than a synthetic receipt claim.
3. **T22 overload-shed + reserve reconfirm (Y/N):** r5 §12.5 items 2/4 still
   HOLD, but G2 now includes fence chain-presence (§5.1) and the shared outlet
   couples adjudicated+delegated (§3.5 item 2). Owner reconfirms the
   predeclared overload-shed class covers q0 coupling loss, or directs the
   split. Blocks S7.
4. **STALE-UNCERTAIN close-out (owner assigns, S-team executes):** C07 (2,797ns
   derivation — read #8276 artifacts, 10 min), C08 (111ns recorded values —
   run `cargo bench --bench b2_capture_bridge` on loss, 30 min, NOT a lane
   task), C38 (17-field binding — read `worker_queue.rs` + diff vs r2 §4.4,
   15 min), C51 (`resolve_ifindex` totality — `(0,0)` fallbacks EXIST at
   `fib.rs:487,511`, cited test unlocated; S6 re-states or strikes r5 §6.12),
   merge SHAs for #10302/#10308/#10391 (parent fills from `docs/log/*.md` +
   `git log --grep`), b2 bound literals vs live consts (grep
   `MAX_PENDING_WORKER_COMMANDS` + `DEFAULT_QUEUE_DEPTH`, 5 min). C51 blocks S6;
   others block nothing but must close before T22 sign-off.

### 9.2 Kill criteria (honored, with proof obligations)

- **K1 (coexistence):** if NO placement admits divert-before-fence on the
  required hooks without reopening leave-alone transit or bypassing the fence
  (any §2.3 conjunct i–v fails and S3 cannot repair by match-set/priority
  tightening), the plan KILLS the divert scope. Proof obligation: the S3 spike
  measurement showing the failure (packet traces + nft dumps + verdict logs),
  filed as the terminal evidence. THIS SECTION IS THE HONORING: r6 analysis
  finds a working placement (§2.2–§2.4), so the plan PROCEEDS to the spike;
  the spike, not this paragraph, is the kill gate.
- **K2 (re-sign):** N/refusal on §6 item 5 or 6 is a PLAN-KILL for this r6
  deliverable (delta memo criterion). Any replacement mechanism requires a
  newly authorized re-plan and hostile review; no silent fallback to r5.
- **K3 (fragment intersection):** S6 first identifies whether #9950 and 9506
  share a hook/keyspace (§8). A proved disjoint intersection is not a failure;
  if they share a hook, any un-reconciled dual overlap tracker, double-drop, or
  split counter kills the fragment scope.
- **K4 (economics):** T22 80%/250µs miss on the loss cluster kills the plan
  (r5 polarity retained, M1/M2 do not renegotiate).
- **K5 (coupling):** if S4 cannot prove-or-split adjudicated/delegated coupling
  (§3.5 item 2) and the coupled loss exceeds the overload-shed budget, S4 KILLS
  the shared-outlet scope (falsifier for option B, §3.4).
- **K6 (q0 mark mechanism):** if the S3 spike's routed-inet q0 cell cannot
  prove queue-zero `queue_mapping == 1` → TC mark `0x58465001` → exact
  `(xpf-usp1,mark)` fence ACCEPT, or q1/unknown clearing fails, the marked-q0
  re-entry scope KILLS. Option B (new TUNs/pinholes) may return only through a
  newly authorized re-plan with a pinhole budget and hostile review; no silent
  fallback or “capture-only” permit is allowed.

---

## Appendix A. Citation index (mechanism claims → master lines)

S1: `pkg/config/compiler_ipsec_plaintext_warn.go:20-22,102-104,120-186`;
`pkg/dataplane/userspace/ingress_exclusions.go:141,150-158,182-184,381-382`;
`userspace-dp/src/server/helpers/planning.rs:345-348,433-448`;
`pkg/daemon/daemon_transit_gate.go:51-56,107-124,133-184,188-197,218-233,246-254,352-411`;
`pkg/daemon/transit_gate_tick_9725.go:56-104`;
`pkg/nftables/transit_barrier.go:11-13,15-28,100-110,124-129,139-175,177-225,227-239`;
`pkg/nftables/netlink_installer.go:25-34`;
`pkg/nftables/host_inbound_reinject_9637.go:19-29`;
`userspace-dp/src/slowpath.rs:23-25,27-38,68-108,110-118,136-154,168-318,974-998,1006-1013,1158-1179,1184-1198,1236-1290`;
`pkg/dataplane/userspace/maps_sync.go:302-306,967-972,1077-1086`;
`pkg/dataplane/userspace/local_address_capacity_9646.go:47-52`;
`userspace-dp/src/afxdp/logical_ingress.rs:79`.
S4.2: above fence/gate rows + `pkg/nftables/rst_suppress.go:114-116`;
`pkg/daemon/daemon_run_bringup.go:670-678`;
`pkg/daemon/transit_cleanup_9725.go:23-24`; `pkg/routing/fibimport.go:16`;
`pkg/daemon/daemon_route_listener.go:16-23`;
`pkg/daemon/transit_gate_link_watch_9848.go:27-95`;
`pkg/daemon/daemon.go:136-143,1691-1694`;
`pkg/nfqueue/nfqueue.go:63-65,67-70,192-202,315-343,345-381,620-673`;
`pkg/dataplane/userspace/interfaces.go:856`.
VRF/input scope: `pkg/daemon/daemon_run_routehelpers.go:690-745`;
`pkg/daemon/daemon_apply_interfaces.go:330-344,372-375`;
`pkg/config/junos_host_deny.go:880-890`;
`pkg/dataplane/userspace/junos_host_vrf_scope_6619_test.go:16-21`;
`pkg/dataplane/userspace/zones_host_inbound.go:165-233`;
`pkg/daemon/daemon_nft.go:521-545,558-582`;
`pkg/nftables/netlink_hostinbound.go:27-78`;
`pkg/nftables/netlink_hostinbound_ingress_9637.go:31-52`;
`pkg/daemon/daemon_nft.go:776-798`;
`pkg/daemon/daemon.go:1025-1045`;
`pkg/nftables/host_inbound_counters.go:13-17`.
S4.5: slowpath + fence rows above +
`userspace-dp/src/slowpath.rs:120-123,755-758`;
`userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs:8-18,138-150`;
`pkg/config/compiler_ipsec_trafficselector.go:39-65`;
`pkg/nftables/transit_barrier_9852_test.go:102-193`;
`pkg/daemon/transit_fence_10302_test.go:54-68`;
`pkg/daemon/README.md:2196-2201`;
`pkg/nfqueue/tunsink.go:11-15`; `pkg/nfqueue/nfqueue.go:14-18,37-45,59-70,118-129,390-466`;
`userspace-dp/src/afxdp/types/forwarding.rs:708-709`;
`userspace-dp/src/afxdp/forwarding/tests.rs:4977-4983`.
S8: `pkg/nfqueue/measure_stages_test.go:24-42`;
`pkg/nfqueue/measure_memory_test.go:26-31`;
`pkg/nfqueue/measure_teardown_test.go:10-79`; fence/gate rows above.
Fragments: `userspace-dp/src/fragment_overlap/mod.rs:1-8,300-304,556-560`;
`userspace-dp/src/afxdp/worker/mod.rs:1556-1561` (counter slots).
Advisory: `pkg/config/compiler_ipsec_plaintext_warn.go:102-104,176-185,193-233`.

*(End of r6 plan. Retained r5 sections are incorporated by reference per §8;
no struck sentence is cited by any S1+ slice.)*
