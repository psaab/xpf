# #9506 — Route-based IPsec decrypted-ingress capture/re-entry bridge (PLAN ONLY, r3)

## 0. Status

**PLAN r3** — no production code. Revision 3 (final planned round) of the
triple-review planning artifact for `psaab/xpf#9506`, after round-2
hostile review (Codex: NEEDS-MAJOR; GLM: NEEDS-MINOR — raw verdicts in
`reviews/codex-r2.txt`, `reviews/glm-5.3-r2.txt`). Neither round-2 review
is a PLAN-KILL; both converge on the same substance and differ only in
severity. Successor to closed #8276 (priced only) and umbrella #7167
(closed NOT_PLANNED, not fixed).

- Branch: `research/9506-xfrm-capture`, base `origin/master 7ef226474`.
- What changed in r3 (codes C2x = Codex r2, Nx = GLM r2): unified
  three-way verdict disposition replacing the permit-release/TUN
  contradiction (C2A/N1); shadow redefined as divert-hold with
  ACCEPT-always, AF_PACKET removed from the plan (C2B/N2); generation
  bound to queue instances with verdict-issue as the linearization
  point, T17 replaced (C2C/N6); overlapped (double-buffered) pipeline
  specified, stop-and-wait prohibited (C2-§5); B1 claims separated
  into demonstrated/conditional/untested (C2-§4); numerical T22 gates
  (C2-§5); verdict-loop B-invariance stated (N3); chain-presence
  overhead row (N4); per-tunnel queues (N5); fragment end-to-end
  semantics (C2-§6); worker dispatch rule (C2-§7); checksum/offload
  contract (C2-§7); TUN-exclusion inversion fixed (C2-§7);
  supervisor-side observability (C2-§7); lifecycle/ordering contract
  (C2-§3); citation drift fixed (N7/C2-§7).
- Gate: hostile review by `zai/glm-5.3` + `openai-codex/gpt-6-astra`,
  raw outputs in `reviews/`. This is round 3 of max 3.

## 1. Framing

Route-based IPsec (`bind-interface stN`, the only IPsec model xpf supports
since policy-based `then permit tunnel` is hard-rejected per #3114)
decrypts in the kernel XFRM stack. Plaintext surfaces on the `xfrmi`
netdev, which is **excluded from AF_XDP ingress adjudication in both
planes independently** (Go `pkg/dataplane/userspace/ingress_exclusions.go`
`SecureTunnel` class via `userspaceSkipsIngressInterface` gating
`buildUserspaceIngressIfindexes`; Rust `planning.rs`
`include_userspace_binding_interface`). The armed kernel-forward path is
**deliberately open** (`daemon_transit_gate.go` removes the barrier when
armed; the barrier exists only while unarmed when `ip_forward` is already
0 — `transit_barrier.go:36-39`). Admission is warning-only
(`compiler_ipsec_plaintext_warn.go:120-191`).

Net effect: an authenticated peer's inner packets reach kernel-routed
destinations with no zone policy, no session, no NAT, no screen, no
counter, no deny event. Disclosed (`docs/userspace-dataplane-gaps.md`,
commit-time advisory), unremediated, high-severity, no active owner.

Round-2 correction, stated plainly: r2 named the denial mechanism but
left the *permit* half holding two egresses at once (verdict-release
AND TUN re-inject). A plan whose tests cannot tell which wire a
permitted packet leaves on is not implementable. This revision replaces
both with one three-way verdict contract (§4.2).

## 2. Honest scope and value, with absolute numbers

If built and gated: every decrypted-ingress inner flow evaluated against
the tunnel's zone policy before session/flow-cache lookup, disposed by
exactly one verdict (DROP / ACCEPT / REINJECT), with permit/deny
evidence, IPv4 + IPv6, host-bound included, multi-tunnel isolated.
Unmeasured: kernel-half cost, owned-frame adjudication cost,
TUN-write cost — all committed as gate rows, none spent as budget.

Budget (r2 derivation retained; round-2 precision fixes applied):

- 2,797 ns is the reciprocal of #5275's whole-box throughput — a scale
  reference only, never spendable. The bridge allowance is incremental:
  sustained tunnel throughput ≥ **80% of the pre-bridge same-topology
  baseline** on the loss cluster, p99 added latency ≤ **250 µs**
  (covers the 100 µs flush cap + verdict loop + one TUN write on the
  REINJECT path). Both numbers are gate-ratified: G2 re-measures the
  baseline on the same boxes and either confirms or kills (C2-§5).
- Per-thread attribution; binding constraint = worse thread.
- Verified bench facts: ~111 ns same-thread rows already include the
  copy; cross-thread consumer reads only `f.len()`; cross-thread row
  uses `sync_channel` vs production's mutex `VecDeque`; no batched row
  exists (`X/B` is hypothesis); 4096 × 1504 B = 6.16 MB (5.88 MiB).
- The verdict-issue loop (`recvmsg` per drained packet + verdict
  `sendmsg` per packet) is **B-invariant**: there is no mainline
  batched-verdict NFQUEUE API. B amortizes the capture→worker wake
  only. The G2 kill criterion therefore tests whether NFQUEUE's
  per-packet API cost is affordable *at all* — B cannot rescue a
  B-invariant term (N3). If the syscall pair alone busts the floor, B2
  is dead per Q1.
- Sustained-flood floor B ≥ 8 (target 8–32, bound 64); timer-flushed
  partials measured in the occupancy distribution; B=3 struck as dead.

## 3. Shipped work (not re-proposed)

- #8276 / PR #8604: pricing instrument; kernel half explicitly unpriced.
- #7167 adjudication: case against naive AF_XDP attach, refreshed for
  #7497, with round-2 honesty classes (C2-§4) — **demonstrated**:
  (a) Ethernet-only `parse_l2` before the ingress-set gate misparses
  raw-L3; (b) half-admission impossible (ingress map without READY
  binding ⇒ `drop_degraded_transit`); **conditional**: (c) one-shot
  `COPY_ONLY` bind with no fallback black-holes *if* copy-mode attach
  fails; (d) no-egress ⇒ recycle *for tunnel-originated ingress*
  (the commentary warns the blanket `missing_egress_binding` account
  was wrong for LAN-to-tunnel traffic — corrected here); **untested**:
  (e) whether copy-mode XSK comes up on `ARPHRD_NONE` at all
  (explicitly unclaimed in-tree; needs a live NIC). Live guards:
  `secure_tunnel_adds_nothing_to_the_binding_plan`,
  `binding_candidate_excludes_secure_tunnel`. Pre-#7497 global queue
  collapse retired with its guard. Inherited: adjudication identity ≠
  binding admission; the re-entry TUN (§4.5) must never enter the shim
  ingress map.
- #8274: owned-frame entry pattern + #6682 unzoned guard.
- #7949: snapshot visibility (egress half); ingress advisory stays
  until enforcement is real. #7191/#5275: unarmed-only barrier;
  load-bearing bypass. #7480: `NoRoute`-arm denial respected; the
  permit-all-defaults outbound residual stays out (§9). #7497:
  per-interface `min(rx_queues, 16)`.

## 4. Concrete design

### 4.1 Order

Authority (§4.2) → handoff pipeline (§4.3) → adjudication entry (§4.4)
→ re-entry (§4.5) → phasing (§4.6) → prohibitions (§4.7). No section
assumes what an earlier one has not supplied.

### 4.2 Transport + closure: scoped NFQUEUE divert; ONE three-way verdict contract

Divert rules (exact, checkable): `forward`: `iifname == <stN> → queue`;
`input`: `iifname == <stN>` with host destination → `queue`. Untouched:
outbound (`oif == stN`, match is on `iif`); SNAT/`accept_local` frames
(different ingress); #7409 reinject (inject path, never `iif == stN`)
— asserted here, pinned by [P] tests with the divert live (T12), never
trusted on assertion alone (C2-§3). The refuted object is the
*unconditional policy-DROP chain*; the divert carries no verdict, drops
nothing by rule, and closes the bypass *by hold*, verdicts deferred to
the adjudicator. Q7 + T12 pin the exact rule set against drift.

**Disposition contract (unified, C2A/N1).** Every held packet receives
exactly one verdict:

- **DROP** — deny. The held original dies in the queue. No second
  copy exists anywhere. This is the whole deny path.
- **ACCEPT** — permit with no userspace mutation (no NAT rewrite and
  kernel FIB route == adjudicated route). The kernel forwards/delivers
  the held original. No TUN involved.
- **REINJECT** — permit requiring userspace-applied mutation (NAT
  address/port rewrite, or VRF/table selection differing from kernel
  FIB — load-bearing for T3's overlapping prefixes): userspace writes
  the mutated frame to the instance-bound re-entry TUN (§4.5) and the
  held original receives DROP. Issue order is write-then-verdict; a
  crash between the two leaves the original held until queue
  timeout/release, which the kernel drops (fail-closed). Exactly one
  wire per packet in every outcome.

Coverage of the contract: modified packets ⇒ REINJECT (IP-header
mutation applied uniformly to all fragments of a datagram; a permit
needing L4-dependent mutation on a non-first fragment ⇒ DROP-and-count,
documented limitation); host delivery ⇒ input-hook verdicts are
DROP/ACCEPT only (a host-bound flow needing mutation ⇒ DROP-and-count,
documented limitation); fragment completion ⇒ one verdict class per
datagram applied to every held fragment (§6.8); errors/cancellation ⇒
verdict-issue failure leaves the packet held ⇒ kernel drops on
timeout/release (fail-closed). T2/T11/T15 are authored against this
contract and no other.

Generation and linearization (C2C/N6): **generation binds to the queue
instance, not the packet stamp.** Rotation creates a new queue under
the new generation and detaches the old (pending ⇒ kernel-dropped,
fail-closed). Packets are identified with their queue's generation by
construction — no retrospective stamping of kernel-buffered packets.
The **linearization point is verdict issue**: demotion before a
packet's verdict is issued ⇒ DROP-and-count; demotion after an ACCEPT
was issued ⇒ the packet was authorized under a live generation at
issue and the kernel owns it (valid — T17's "post-verdict
pre-transmit cancellation" is struck as unimplementable: no
enforcement point exists past release, and the plan no longer
pretends one does). The physical fence is quiesce-before-issue on the
capture thread for orderly demotion, or demotion-time arm-down
(downstream drops) for abrupt loss; the gate picks the default.
"A verdict already sent to the kernel cannot be recalled" is stated
once, here, and §6.5 no longer claims otherwise.

Lifecycle/ordering (C2-§3): the divert transfers disposition authority
and can drop on failure — safety comes from scope + lifecycle, never
from "carries no verdict". Divert install failure uses a DIFFERENT
contract than the transit barrier's tolerated failure: the barrier is
belt-to-braces over an already-closed window, while an authoritative
divert that fails to install leaves the tunnel DOWN (fail-closed),
never open-forwarding. Rule ownership and atomic ordering against
tunnel create/activate/replace/teardown and daemon restart: divert
lifecycle is tied to snapshot generation — after restart, closed until
the divert is re-resolved and confirmed. The input twin orders before
host-inbound policy (it supplies packets TO policy, a stated ordering
requirement + test).

Fairness (N5): **per-tunnel queues** (isolation over thread economy;
thread count bounded by a stated tunnel max, over-max ⇒ tunnel stays
down, counted). One shared queue would make one tunnel's flood
head-of-line-block the rest — chosen against, with a per-queue-depth
counter and test.

### 4.3 Handoff pipeline: batched AND overlapped (stop-and-wait prohibited)

Batching amortizes the capture→worker wake; it never amortizes the
B-invariant socket half (§2). The pipeline is double-buffered:
bounded in-flight depth ≥ 2 batches — the capture thread drains batch
N+1 while the worker adjudicates batch N — with a bounded
worker→capture verdict queue. The capture thread NEVER blocks on the
worker: full verdict/batching queue ⇒ try-or-drop-and-count
(fail-closed). R1/r2's "drain → wait → issue → drain" read is
explicitly prohibited as an implementation shape (C2-§5). G1/G2 rows
cover the real pipeline: batched send, cross-core payload read,
verdict-queue behavior under overload, mixed permit/deny traffic
(never clean-permit synthetics alone).

Heap: pooled slabs, no hot-path allocation; batch rows carry (slot,
len, tunnel key, flow key, queue-generation); byte/slot bounds sized
for 64-frame commands. Saturation: bounded, non-blocking producer,
refuse-at-bound, drop-and-count, control-command progress fenced from
batch occupancy, mutex acquisition try-or-drop, telemetry rate-bounded.

Same-thread adjudication stays rejected as a *gated model* (starvation
risk, symmetric fairness row, explicit reopen condition).

### 4.4 Adjudication entry: owned-frame path on the worker

#8274/#8062 pattern: each frame enters before flow-cache/session and
before policy, on tunnel logical ifindex + zone + routing
instance/table + RG identity; outer ESP/IKE session implies nothing
inner. Framing: `ARPHRD_NONE` raw-L3 with explicit L3-offset
representation — never the Ethernet-assuming shim parse. Loop-body
extraction threads `binding` through 17 fields behind a batch-drain
call with a batches-per-poll-cycle fairness bound. Owned entry builds
recyclable pool-slot descriptors (never fake addrs) and carries the
inner L3 byte count (§6.9). Checksums: the worker verifies inner
IP/L4 checksums on the owned frame (cost inside the G1 adjudication
row) — failure ⇒ drop-and-count; GRO/GSO super-frames are
refused-and-counted, never segmented in userspace (scope guard, §6.8).

Dispatch rule (C2-§7): a batch is processed wholly on one worker;
worker selection reuses the physical-path dispatch function on the
flow key (named at implementation, behavior pinned here); inner
sessions are owned by the adjudicating worker with reverse flow
dispatched by session lookup exactly as physical paths do; fragments
share the datagram key so reassembly affinity holds. NAT/session
ownership follows the session owner. Verdicts issue in capture order.

### 4.5 Re-entry: TUN exists ONLY for REINJECT

The per-worker re-entry TUN carries exactly the REINJECT-modified
forward-path frames, bound to the adjudicated routing instance. It is
a refused-dataplane netdev by construction: excluded from the shim
ingress map, the binding plan, and the RSS/AF_XDP allowlist via a
dedicated exclusion class, and LISTED in the refused-netdev index
(r2's "excluded from the refused index" was an inversion — corrected,
C2-§7) so no alias row can smuggle it back. Half-admission is
impossible by §3(b): the TUN never enters the ingress set, so no
`BINDING_MISSING` drop can arise from it.

### 4.6 Phasing: shadow (ACCEPT-always) → enforcing → closed-by-hold

1. **Shadow**: divert live, every verdict issued is unconditional
   ACCEPT (a DROP would be enforcement), kernel forwards originals
   exactly as today, adjudication runs and counts divergence, NO
   re-entry machinery runs. Exactly-once holds by construction
   (verified, N-construction). Shadow is load-bearing for
   availability: the divert holds packets in every phase, so reader
   death or queue-full in shadow drops tunnel traffic that used to
   forward (NFQUEUE with no bound socket drops by default — on the
   plan's side, but STATED and tested per phase, never inherited by
   luck, N2a). Phase is part of the stamped context: a batch captured
   in shadow completes under shadow semantics even if the flip lands
   mid-batch; shadow-created sessions invalidate at the flip (N2b).
   Shadow→enforcing transition has its own test.
2. **Enforcing**: verdicts released per §4.2; parity proved on real
   traffic (§8); advisory removed in the SAME change (else a second
   untruth); in-source #8276 references updated to #9506.
3. **Closed-by-hold**: no separate close step exists — the bypass is
   gone *because* the divert holds every `iif == stN` packet. There is
   no second mechanism for the refuted chain to return through.

Bring-up or runtime failure (queue refused, reader/worker/socket
death, per phase incl. shadow): IPsec dataplane closed +
operator-visible, never silent Linux forwarding. Observability
survives the reader: counters and queue stats (drops, depth via
netlink) live in the daemon supervisor, published on supervisor
ticks and reader-heartbeat loss — a dead thread is never the
publisher of its own death (C2-§7).

### 4.7 NOT proposed

- No unconditional policy-DROP forward chain live while armed; the
  only armed footprint is the scoped divert, rule set pinned by Q7+T12.
- No AF_XDP attach to the xfrmi (§3 classes); no AF_PACKET-tap
  enforcement — the tap is REMOVED from this plan (shadow subsumes
  observation; C2B).
- No userspace ESP decryption; no selector-as-policy.

## 5. API preservation

Config/CLI unchanged; phase + shadow-divergence exposed via existing
telemetry/show surfaces. Internal extension additive: batch-queue
type, packet-bearing command variant, owned-frame entry, per-tunnel
queue-draining capture threads, divert lifecycle tied to generation.
Queue bounds 4096/16384 joined by byte/slot bounds for 64-frame
commands. No second reader on the slow-path channel. Telemetry
additive and rate-bounded (per-queue depth, verdicts by class,
shadow-divergence, flush-timer histogram, inner attempted/forwarded,
generation-fenced drops, recirculation refusals).

## 6. Hidden invariants

1. Bounded, fail-closed handoff (try-or-drop enqueue; control
   progress fenced; rate-bounded telemetry).
2. Tunnel-identity adjudication (logical ifindex + zone + instance/
   table + RG; never outer phys zone).
3. Pipeline order (inner before flow-cache/session/policy; outer
   session implies nothing).
4. Exactly-once egress per phase; no recirculation (§4.2/§4.5).
5. Generation bound to queue instances; verdict-issue linearization;
   quiesce-before-issue / arm-down fences; rotation drops pending +
   fragment state (§4.2).
6. Bring-up AND runtime failure fail closed per phase,
   operator-visible, supervisor-published (§4.6).
7. HA, RG-scoped: per-node per-RG capture; standby reader stopped;
   abrupt failure orphans die held (fail-closed); new owner
   re-resolves before starting, adjudicates nothing until then; no
   cross-tunnel leakage (per-VRF).
8. MTU/fragments/GRO: super-frames refused-and-counted; jumbo slab
   sizing; TUN-MTU writes fail-closed + counted. Reassembly contract
   (C2-§6): located in the worker post-capture pre-policy; hooks see
   fragments (no kernel defrag assumed before the hook — assumption +
   test); completion authorizes per-fragment verdicts of one class,
   never a merged super-datagram ("first-wins + count" = first-seen
   bytes win, later overlaps dropped-and-counted, explicit v4/v6
   overlap semantics at implementation); keys include tunnel + VRF +
   flow-id + generation/epoch; rotation drops pending state;
   initial caps ≤1024 datagrams/tunnel, ≤64 KB each, 2 s expiry —
   gate-validated, kill-linked if incompatible with the handoff
   budget. Non-first fragments never permit alone; ICMP errors are
   their own flow.
9. Counters: inner L3 bytes; attempted (fragments as received) vs
   forwarded (fragments released) distinct; duplicates excluded by
   exactly-once; outer ESP never attributed inner; permit AND deny
   parity.
10. #7480 outbound ordering untouched; permit-all outbound residual
    out (§9).
11. `resolve_ifindex` totality; `(0,0)` collapse test-pinned
    impossible.
12. Ownership-keyed divert resolution
    (`SecureTunnelNetdevForRef` ∪ `liveXfrmNetdevs`), never name
    shape; unowned `st5` never diverted (T18).
13. Re-entry TUN refused-dataplane class, listed refused, never in
    the ingress set (§4.5).
14. Worker fairness: batches-per-poll-cycle cap; gated measurement.
15. Input-twin orders before host-inbound policy (stated + tested).
16. Divert install failure ⇒ tunnel DOWN (distinct from the barrier's
    tolerated-failure contract); lifecycle tied to generation;
    restart ⇒ closed until re-confirmed.

## 7. Risk table

R1 bypass-path miss → ownership-keyed per-rotation re-resolve;
recreate/move/demotion tests; unresolvable REFUSED. R2 double
delivery → single verdict contract + per-phase exactly-once tests.
R3 drift → inner-L3 plumbing, parity both sides, revocation test.
R4 kernel-half cost → gate first; B-invariant kill phrasing (Q1).
R5 batch latency → 100 µs cap + occupancy + T22/T19. R6 pool
contention → sharded pools + rows. R7 flood drops → specified,
sized, fenced progress. R8 armed-path breakage → scoping + T12[P]
with divert live; drift kills the change. R9 failure bricks closed →
visible error + runbook + per-phase T14. R10 HA staleness → per-RG
per-node capture, instance-bound generations, demotion/abrupt tests.
R11 MTU/fragment/GRO → §6.8 contract + T20; budget kill-linked.
R12 advisory mistiming + invisible divergence → same-change rule,
per-phase tests, divergence counters.

## 8. Test plan (fail-on-revert; loss cluster; never faked)

Gates: G1 — cluster re-run of `b2_capture_bridge` + committed new
rows: batched send (8/16/32 + timer-flushed singles distribution),
cross-core payload read, owned-frame adjudication incl. checksum
verify (absorbs r1 Q2), TUN-write row (N1), overlapped-pipeline
behavior (in-flight ≥2, verdict-queue overload, mixed permit/deny),
fairness row, per-core attribution (binding = worse thread). G2 —
NFQUEUE divert + verdict-loop on real SAs (v4/v6, NAT-T/native ESP,
both hooks, B = 8/16/32): per-diverted-packet cost AND chain-presence
overhead on non-tunnel forwarded traffic (N4); kill phrasing: if the
B-invariant socket half alone busts the T22 floor, no B saves it —
B2 dead per Q1.

Enforcement (each names its reverted mechanism; [P] preservation
tests pass today): T1 deny v4/v6 (revert: divert rule deletion).
T2 permit incl. REINJECT path with wire-verified mutation (revert:
verdict-contract change). T3 per-VRF attribution. T4 app/port deny.
T5 host-bound both verdicts. T6 fragments incl. split batches,
non-first never permits, ICMP-own-flow. T7 two-tunnel isolation. T8
saturation closed + recovery. T9 bring-up refusal ⇒ tunnel down.
T10 recreate/move/demotion orderly+abrupt; unresolvable REFUSED;
verdict-issue linearization (replaces r2 T17 — post-release
cancellation struck as unimplementable). T11 no-recirculation +
per-phase exactly-once. T12[P] armed paths + `oif == stN` outbound
with divert live; exact-rule-set scope pin. T13 advisory per phase +
#8276 reference updates. T14 runtime death per phase incl. shadow
(N2a) — routed AND host-bound never forward unadjudicated. T15
exactly-once under flood + flush scheduling. T16 revocation incl.
phase-flip invalidation (N2b) + flip-ordering test for in-flight
batches. T17 intent-fencing at verdict issue (renumbered; old
cancellation semantic struck). T18[P] alias preservation + unowned
`st5` keeps AF_XDP. T19 flush-timer histogram under contention. T20
GRO/jumbo/over-TUN-MTU refused-counted-never-truncated. T21
deny-side parity. T22 numerical floors: ≥80% baseline throughput,
p99 ≤250 µs added (gate-ratified). Per-transport coverage: suite runs
the NFQUEUE shape; no tap exists to cover (tap removed).

## 9. Out of scope

Userspace ESP decryption. Policy-based IPsec. Unconditional armed
forward chains. AF_XDP on xfrmi. AF_PACKET entirely (removed r3).
WireGuard kernel-path residual; #8279 TUN admission. Selector- or
`allowed-ips`-as-policy. Shape-B outbound under permit-all (#7480
residual; value claims exclude it). Flowtables. Cross-node capture
sync; standby adjudication. Re-tuning the scale. L4-mutation on
non-first fragments; mutated host-bound flows (DROP-and-count
limitations, §4.2).

## 10. Open questions (each invites PLAN-KILL)

1. Does the NFQUEUE per-packet API cost fit at all? B rescues the
   wake, never the socket half — third authoritative transport or
   B2 dead?
2. Who owns the flush timer under NAPI pressure — enforceable
   without a per-packet wake, or is the cap fiction?
3. Generation primitive selection among pinned behaviors (queue
   instances + verdict-issue linearization fixed; primitive =
   snapshot generation vs RG-epoch vs tuple — implementation
   selection, N6; does NOT block approval).
4. Do the 25 `desc.len` counters enumerate completely — wider
   refactor ⇒ kill or re-scope?
5. Does the bounded-reassembly budget fit — which side gives if not,
   and is drop-non-first acceptable, stated where?
6. NFQUEUE depth vs burst: what depth avoids fail-always without
   breaking T22, and is per-tunnel sizing administrable?
7. What pins the divert rule set against future "one more match" —
   T12's scope test, and is it sufficient as the ONLY guard?

## 11. Acceptance

- Converged plan on the branch with both reviewers at PLAN-READY
  (or reported split), raw verdicts in `reviews/`.
- G1+G2 pass on the loss cluster with per-core attribution; T22
  numbers confirmed or plan killed; no `X/B` table cited as pricing.
- Implementation PR (separate, not this plan) carries T1–T22 green
  on real traffic (enforcement/[P] split honored), no faked numbers,
  same-change advisory removal + #8276 reference updates.
