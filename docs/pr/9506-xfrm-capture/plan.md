# #9506 — Route-based IPsec decrypted-ingress capture/re-entry bridge (PLAN ONLY, r4)

## 0. Status

**PLAN r4** — no production code. Revision 4, one targeted round
authorized by parent on Codex-r3-terms ("re-plan the disposition/
lifecycle core — the gaps are architectural, not editorial"), after a
round-3 split (Codex: NEEDS-MAJOR; GLM: NEEDS-MINOR — raw verdicts in
`reviews/codex-r3.txt`, `reviews/glm-5.3-r3.txt`). Neither review is a
PLAN-KILL; both retain NFQUEUE as the research candidate. Successor to
closed #8276 (priced only) and umbrella #7167 (closed NOT_PLANNED).

- Branch: `research/9506-xfrm-capture`, base `origin/master 7ef226474`.
- What changed in r4 (Cx = Codex r3, Hx = GLM r3): disposition-specific
  commit points with attempted/successful/uncertain submission, REINJECT
  linearized at TUN submission (A); supervisor deadline + explicit
  teardown, no per-packet-timeout reliance (A); worker×instance TUN
  model with bounds (B); second-traversal accounting — TTL
  compensation, mark save/restore, policy-free post-TUN topology,
  route-stability fence at commit (B); drain-before-activation flip
  with transitional epoch, receive-time phase sampling, cancel-over-
  ACCEPT precedence, quarantined shadow sessions (C); full queue
  lifecycle protocol — quarantine, atomic swap, listener lifetime,
  epoch-tagged verdict identifiers, in-flight classification,
  snapshot coordination (D); derived T22 workload + stage-rate
  analysis (E); batch-verdict factual correction — implementation
  selects and prices the verdict API, plan asserts nothing (E);
  out-of-order verdicts with per-flow FIFO + separate fragment slots
  (blocking); owner-homogeneous sub-batches (blocking); v6
  overlap-drop + v4 hole-tracking (blocking); repriced reassembly
  budget + stated tunnel max (major); shadow failure table (H2);
  counter-pinning + local-address-set lifecycle (H6); metadata/
  conntrack residuals (H3); class-stickiness + reorder bound (H4);
  queue-timeout ownership (H5); phase-in-tuple (H1).
- Gate: hostile review by `zai/glm-5.3` + `openai-codex/gpt-6-astra`,
  raw outputs in `reviews/`. Round 4 of max 4 (one targeted extension).

## 1. Framing

Route-based IPsec (`bind-interface stN`, the only IPsec model xpf supports)
decrypts in kernel XFRM; plaintext surfaces on the `xfrmi`, excluded from
AF_XDP adjudication in both planes (`ingress_exclusions.go` SecureTunnel
class; `planning.rs` `include_userspace_binding_interface`); the armed
forward path is deliberately open (`daemon_transit_gate.go` removes the
barrier when armed); admission is warning-only. An authenticated peer's
inner packets forward with no policy/session/NAT/screen/counter/deny —
disclosed, unremediated, high-severity, no active owner.

Round-3 correction, stated plainly: r3's "verdict-issue linearization"
was wrong for REINJECT (the TUN write authorizes before any verdict is
issued), "exactly-one-wire" overclaimed crash semantics, and several
lifecycle sentences named properties without mechanisms. This revision
replaces the single linearization point with a per-disposition commit
table and gives every lifecycle claim a protocol.

## 2. Honest scope and value, with absolute numbers

If built and gated: every decrypted-ingress inner flow disposed by
exactly one verdict (DROP / ACCEPT / REINJECT) against the tunnel's zone
policy, with evidence, v4+v6, host-bound included, multi-tunnel
isolated. Unmeasured: kernel-half cost, adjudication cost, TUN-write
cost — all gate rows, none spent as budget.

Budget (r2 derivation retained; r4 corrections):

- 2,797 ns = whole-box reciprocal, scale reference only. Allowance is
  incremental: T22 floors (derived in §8, not asserted here).
- Per-thread attribution; binding = worse thread.
- Verified bench facts: 111 ns rows include the copy; cross-thread
  consumer reads only `f.len()`; cross-thread row is `sync_channel`
  vs production mutex `VecDeque`; no batched row exists.
- The verdict-issue path is priced as two terms with different
  B-dependence: the capture→worker wake (per-batch, B-amortized) and
  the socket half (per-packet objective cost whose batching depends on
  the verdict API the implementation selects — see below). G2's kill
  phrasing: if the B-invariant portion alone busts T22, no B saves it.
- **Factual correction (Cx-E):** r3 claimed "no mainline batched-verdict
  NFQUEUE API". The reviewer asserts batch/cumulative verdict support
  exists; this box carries no libnetfilter_queue headers to check
  against, so this plan asserts NOTHING about API availability. The
  implementation selects per-packet and/or batch verdict calls and
  prices the chosen shape in G2. Constraint the plan does impose:
  cumulative batch semantics cannot express arbitrary mixed
  dispositions — mixed batches use per-packet verdicts, or
  disposition-homogeneous grouping where the API allows it. The
  economics section prices the chosen shape; it never denies a
  capability again.
- Floor B ≥ 8 sustained (target 8–32, bound 64); timer-flushed partials
  in the occupancy distribution; B=3 dead.

## 3. Shipped work (not re-proposed)

#8276/#8604 instrument (kernel half unpriced). #7167 anti-AF_XDP case in
demonstrated/conditional/untested classes (r2 §3 retained). #8274
owned-frame pattern + #6682 guard. #7949 snapshot visibility. #7191 /
#5275 unarmed-only barrier; load-bearing bypass. #7480 NoRoute-arm
denial; permit-all outbound residual out (§9). #7497 per-interface
queues. #9646 local-address capacity gate (reused §6.12).

## 4. Concrete design

### 4.1 Order

Authority + commit points (§4.2) → handoff pipeline (§4.3) →
adjudication entry (§4.4) → re-entry TUN contract (§4.5) → phasing
(§4.6) → prohibitions (§4.7).

### 4.2 Transport, closure, and the commit table

Divert rules (exact, checkable): `forward`: `iifname == <stN> → queue`;
`input`: `iifname == <stN>` + host-destination (match set = the
`buildDesiredLocalAddressSets` enumeration that already feeds
`userspace_local_v4/v6`, per generation, #9646 capacity-checked; stale
entries purged on rotation — H6) → `queue`. Untouched: `oif == stN`
outbound, SNAT/`accept_local` ingress, #7409 reinject — asserted,
pinned by [P] T12 with divert live. Refuted object = unconditional
policy-DROP chain; divert carries no verdict, drops nothing by rule.
Q7 + T12 pin the rule set against drift.

**Commit table (Cx-A — replaces r3's single linearization point).**

| Disposition | Commits at | Generation fence | Failure between adjudication and commit |
|---|---|---|---|
| ACCEPT | successful verdict submission (syscall success AND queue epoch live at return) | epoch re-check immediately before submission | pre-commit demotion/rotation ⇒ DROP-and-count, never submitted |
| REINJECT | successful TUN `write()` of the full mutated frame | epoch re-check immediately before `write()`; the DROP verdict on the held original afterwards is cleanup, not authorization | pre-write demotion ⇒ DROP-and-count, NO write; crash after write ⇒ permit completes, original dies held (at-most-once) |
| DROP | successful verdict submission (same boundary as ACCEPT) | epoch re-check before submission | same as ACCEPT |

Submission states, distinguished everywhere (Cx-A): **attempted**
(syscall issued), **successful** (returned success with epoch live),
**uncertain** (syscall error, or epoch rotated mid-call, or return
status ambiguous). Uncertain ⇒ counted as uncertain and resolved
fail-closed: the packet is never assumed disposed; supervisor
reconciliation (queue-stats audit + teardown default of drop) converges
it to dropped. "Exactly-one-wire" is struck as a guarantee and
replaced with **at-most-once emission + fail-closed convergence**:
zero deliveries (pre-commit crash) and one delivery are the only
outcomes the design produces; duplicates are structurally excluded
(the original cannot leave before its verdict; the replacement exists
only after a committed write); uncertain outcomes converge to dropped.

**No per-packet-timeout reliance (Cx-A).** NFQUEUE supplies no generic
per-packet timeout and the plan no longer implies one. The bound is a
**supervisor verdict deadline: 50 ms from capture** (tunable,
gate-validated). Expiry ⇒ supervisor teardown sequence: detach rule →
drain-or-deadline old queue → destroy queue → confirm destruction;
pending packets die with the queue (kernel default). Teardown is a
tested mechanism (T10/T14), not a sentence.

**Route-stability fence at commit (Cx-B).** The FIB-vs-adjudicated
guarantee under PBR/ECMP/concurrent change is bounded honestly: the
worker re-resolves the route at commit; mismatch with the adjudicated
route ⇒ DROP-and-count (route-flap fail-closed) + counter. Guarantee =
"egress realizes the adjudicated route iff the FIB is stable across
the adjudication→commit window; otherwise drop." No stronger claim.

**Queue lifecycle protocol (Cx-D).** Queue numbers come from a
per-daemon allocator as `(number, epoch)` handles with **reuse
quarantine**: a number is not reused until the old listener has exited
AND queue destruction is confirmed AND one full supervisor tick has
passed. Atomic replacement ordering: create new queue → install new
rule → drain-or-deadline old → delete old rule → destroy old queue.
Old listener lifetime: until drain-complete or the supervisor
deadline, then thread teardown + destroy. Verdict identifiers carry
`(number, epoch)`; a verdict addressing a recycled number with a stale
epoch is refused (quarantine + epoch check at send — test-pinned).
Pre-rotation in-flight classification: the diversion boundary defines
the epoch — a packet reaching the hook after the new rule installs
belongs to the new queue even if it entered the stack earlier
(stated, tested). Snapshot coordination: rotation is serialized with
snapshot publication; a worker whose snapshot version is older than
the queue epoch at commit ⇒ DROP-and-count (no verdict from stale
policy, test-pinned).

Fairness: per-tunnel queues (head-of-line isolation); bound stated in
§6 (tunnel max); over-max ⇒ tunnel down + counted.

### 4.3 Handoff pipeline: batched, overlapped, per-flow ordered

Double-buffered in-flight ≥ 2 batches; bounded worker→capture verdict
queue; capture thread never blocks (try-or-drop-and-count,
fail-closed); stop-and-wait prohibited. **Out-of-order verdicts
(blocking Cx finding):** verdicts may issue out of capture order —
capture-order issuance plus held fragments would head-of-line-block
unrelated flows. Constraint retained: **per-flow FIFO** (capture thread
holds per-flow sequence numbers; a flow's verdicts issue in order).
**Fragment slots are a separate bounded pool** from ordinary batch
slots: incomplete datagrams consume fragment ownership, never block
other flows' verdicts; expiry sweeps reclaim. G1/G2 rows: batched
send, cross-core payload read, verdict-queue overload behavior, mixed
permit/deny, chosen verdict-API shape.

Heap: pooled slabs, no hot-path allocation; batch rows carry (slot,
len, tunnel key, flow key, queue-epoch, phase epoch — H1: phase IS a
tuple field). Saturation: bounded, non-blocking, refuse-at-bound,
control progress fenced, mutex try-or-drop, telemetry rate-bounded.
Same-thread adjudication stays rejected as a gated model with reopen
condition.

### 4.4 Adjudication entry: owned-frame path on the worker

#8274/#8062 pattern, before flow-cache/session/policy, on tunnel
logical ifindex + zone + instance/table + RG; outer session implies
nothing inner. `ARPHRD_NONE` L3-offset representation; 17-field
binding threading behind a batches-per-poll-cycle fairness bound;
pool-slot descriptors; inner-L3 byte counts; worker-verified inner
checksums (G1-row cost), GRO/GSO refused-and-counted.

**Dispatch (blocking Cx finding): owner-homogeneous sub-batches.**
A drained batch is partitioned by owner = the physical-path dispatch
function on the flow key; each sub-batch goes to its owner worker
under the same B/100 µs bounds (partials allowed). Whole-batch
single-worker dispatch is prohibited for mixed-flow batches. Reverse
flow resolves via session lookup as physical paths do.
**Fragment-to-session transfer:** reassembly owner = hash(datagram
key); on completion the adjudicating (reassembly-owner) worker creates
the session and owns it; the completed datagram's per-fragment
verdicts execute on the capture thread in per-flow order.

### 4.5 Re-entry: worker×instance TUNs with a forwarding contract

TUNs exist only for REINJECT-modified forward-path frames. **Model
(Cx-B): one TUN per (worker, routing-instance)**, lifecycle tied to
generation, resource bound: workers × instances ≤ 128 (tunnel max 32
× instances-per-tunnel ≤ 4 illustrative; exact product gate-checked);
over-max ⇒ tunnel down + counted. Refused-dataplane class, listed in
the refused-netdev index, never in the shim ingress map.

**Second-traversal accounting (Cx-B), exhaustive:** the held packet
already traversed pre-hook kernel processing (incl. one TTL
decrement); re-injection starts a second traversal. The plan specifies
each item: TTL — userspace compensates +1 pre-write, test pins the
observed wire TTL; DSCP — preserved in-band; fwmark (H3) — saved at
capture, restored via `SO_MARK` pre-write (stated; T2 wire-verified);
conntrack (H3) — sees a fresh flow on the TUN iface: contained by the
**policy-free post-TUN topology** (no policy chains attached in
re-entry instances/VRFs; a test asserts the empty chain set per
re-entry instance every generation — a mark-based accept would be the
refuted chain returning, so topology, not marks, carries this);
NAT already applied in-frame; ICMP errors post-reinject reference the
re-injected frame (stated acceptable); ECMP/route-change races fall
under the §4.2 commit fence.

### 4.6 Phasing: shadow (ACCEPT-always) → drain-before-activation → enforcing

1. **Shadow**: divert live, every issued verdict unconditional ACCEPT;
   adjudication counts divergence; TUN machinery idle. Shadow failure
   table (H2), per worker-failure cell: checksum-fail / unparseable /
   GRO-refused / slab-OOM ⇒ **ACCEPT-with-divergence-count**
   (observation preserved — dropping here would be enforcement);
   worker-dead / queue-full / socket loss ⇒ kernel default-drop,
   counted as **shadow-unavailable** (cannot ACCEPT what was never
   read). T14 authored per cell per phase.
2. **Flip = drain-before-activation (Cx-C):** the flip waits for
   in-flight shadow batches to complete under shadow semantics
   (bounded by the supervisor deadline; remainder cancelled+dropped),
   then activates under a **transitional epoch flag**
   (operator-visible). Phase is sampled at receive — kernel-queued
   packets carry no stamp, and the plan defines receive-time sampling
   as the semantic (Cx-C). **Precedence: generation-cancel beats
   shadow-ACCEPT** for post-flip receives (stated). **Shadow sessions
   are quarantined**: never published to forwarding/NAT state,
   invalidated at flip (stronger than r3; test-pinned).
3. **Enforcing**: verdicts per §4.2; parity on real traffic; advisory
   removed same-change; #8276 references → #9506.
4. **Closed-by-hold**: no separate close step; the divert holds every
   `iif == stN` packet.

Per-phase failure: closed + operator-visible, supervisor-published
(supervisor owns counters/queue-stats/heartbeats; a dead thread never
publishes its own death).

**Class-stickiness (H4):** within an epoch, a flow keeps its first
verdict class; a forced class transition (FIB divergence mid-flow) ⇒
DROP-and-count the transitioning packets (no silent cross-wire
reorder); T2/T3 carry a reorder-bound sub-case measuring the residual
(single-flow ACCEPT→REINJECT boundary reorder where stickiness
cannot apply, e.g. first packet).

### 4.7 NOT proposed

No unconditional armed DROP chain (only the pinned divert rule set).
No AF_XDP on xfrmi (§3 classes). No AF_PACKET anywhere (removed r2→r3,
stays out). No userspace ESP decryption. No selector-as-policy.

## 5. API preservation

Config/CLI unchanged; phase + transitional epoch + divergence via
existing telemetry/show surfaces. Additive internals: batch/sub-batch
queues, packet-bearing commands, owned-frame entry, per-tunnel capture
threads, per-(worker,instance) TUNs, divert + queue lifecycle tied to
generation. Bounds 4096/16384 + byte/slot bounds. Telemetry additive,
rate-bounded (per-queue depth, verdicts by class AND submission state
— attempted/successful/uncertain — shadow-divergence, flush histogram,
inner attempted/forwarded, fenced drops, route-flap drops, quarantine
refusals, uncertain-submission reconciliations).

## 6. Hidden invariants

1. Bounded fail-closed handoff (try-or-drop; control fenced;
   rate-bounded telemetry).
2. Tunnel-identity adjudication (never outer phys zone).
3. Pipeline order (outer session implies nothing).
4. At-most-once emission + fail-closed convergence; no recirculation.
5. Instance-bound generations; per-disposition commit points;
   quiesce-before-issue / arm-down fences; rotation drops pending +
   fragment state; full lifecycle protocol (§4.2).
6. Per-phase closed failure, supervisor-published.
7. HA RG-scoped: per-node per-RG capture; standby stopped; abrupt
   orphans die held; new owner re-resolves first; per-VRF isolation.
8. MTU/fragments/GRO: super-frames refused-counted; jumbo slabs;
   TUN-MTU fail-closed. Reassembly: worker post-capture pre-policy;
   hooks see fragments (no pre-hook kernel defrag assumed — assumption
   + test; if the kernel defrags first on some path, the queue sees
   datagrams and the contract still holds since verdicts apply to
   held packets). Completion authorizes per-fragment verdicts of one
   class; never a merged super-datagram. Overlap (blocking Cx
   finding): **IPv6 — any overlap ⇒ whole-datagram DROP + count**
   (exact duplicates deduplicated + counted; atomic fragments cannot
   overlap by construction); **IPv4 — first-wins with hole-tracking,
   holes at completion ⇒ DROP** (incomplete ≠ forwardable).
   Forwarded set == inspected set always — no
   inspection/forwarding disagreement by construction. Keys include
   tunnel + VRF + flow-id + generation/epoch. Repriced caps (major Cx
   finding): **≤128 datagrams/tunnel × ≤64 KB = ≤8 MiB/tunnel**;
   **tunnel max 32 ⇒ aggregate ≤256 MiB** + slabs/queues stated in
   G2; 2 s expiry; held fragments excluded from T22 latency; sweep
   cost O(caps) bounded. Budget incompatibility kills the plan.
   Non-first fragments never permit alone; ICMP errors own-flow.
9. Counters: inner L3; attempted (fragments as received) vs forwarded
   (fragments released); uncertain submissions counted separately;
   outer ESP never inner; permit+deny parity; limitation counters
   pinned (H6: non-first-mutation drops; mutated-host-bound drops).
10. #7480 ordering untouched; permit-all outbound residual out.
11. `resolve_ifindex` totality; `(0,0)` impossible by test.
12. Ownership-keyed divert (`SecureTunnelNetdevForRef` ∪
    `liveXfrmNetdevs`); unowned `st5` never diverted (T18).
13. TUN refused-dataplane class, listed refused, never ingress ( §4.5).
14. Worker fairness caps; gated measurement.
15. Input twin before host policy (ordered + tested); match set
    lifecycle = snapshot enumeration + #9646 gate + per-generation
    purge (H6).
16. Divert install failure ⇒ tunnel DOWN (≠ barrier tolerance);
    lifecycle tied to generation; restart closed until re-confirmed.
17. Route-flap fail-closed at commit (§4.2 fence).
18. Class-stickiness within epoch (§4.6).

## 7. Risk table

R1 path miss → ownership re-resolve per rotation; tests; REFUSED.
R2 duplicates → commit table + per-phase exactly/at-most-once tests;
uncertain-submission reconciliation test. R3 drift → inner-L3
plumbing; parity; revocation; quarantine. R4 kernel cost → gate
first; B-invariant kill phrasing. R5 latency → cap + occupancy +
T22/T19. R6 contention → sharded pools + rows. R7 flood → specified
drops; fenced progress. R8 armed breakage → scoping + T12[P]; drift
kills change. R9 failure bricks closed → visible + runbook + per-phase
T14 incl. shadow-unavailable. R10 HA → per-RG capture; instance
epochs; demotion/abrupt tests; quarantine. R11 MTU/frag/GRO → §6.8 +
T20; kill-linked budget. R12 advisory/divergence → same-change rule;
per-phase tests. R13 (new) second-traversal divergence (TTL/mark/
conntrack) → §4.5 contract + wire tests. R14 (new) flip-window
enforcement gap → drain-before-activation + transitional epoch +
deadline-cancel tests.

## 8. Test plan (fail-on-revert; loss cluster; never faked)

Gates: G1 — cluster `b2_capture_bridge` + rows: batched send
(8/16/32 + flushed-singles distribution), cross-core payload read,
owned-frame adjudication incl. checksum verify, TUN-write row,
overlapped-pipeline behavior (in-flight ≥2, verdict-queue overload,
mixed permit/deny, chosen verdict-API shape incl. batch-grouping
behavior), fairness row, per-core attribution. G2 — divert +
verdict loop on real SAs (v4/v6, NAT-T/native ESP, both hooks,
8/16/32): per-diverted cost AND chain-presence overhead on non-tunnel
traffic; kill phrasing tests the B-invariant half with no rescue by B.

**T22 derivation (Cx-E).** Workload (fixed for the gate):
IMIX (7×64 B, 4×570 B, 1×1518 B) + 9 KB jumbo sub-case; 8 tunnels ×
4 K flows, bidirectional 60/40; disposition mix 70% ACCEPT / 20%
REINJECT (NAT) / 10% DROP; 5% fragments; 1% host-bound; offered load
to 100% of pre-bridge baseline then +20% overload; loss allowance 0
for ACCEPT/REINJECT-delivered (useful delivered = inner payload
bytes delivered once, in order per flow — processed/dropped excluded);
latency = capture-to-verdict-release per packet at 70% load, drops
excluded + counted separately; 5 runs, ±10% variability bound;
non-tunnel forwarding concurrent ≤5% degradation. Stage-rate analysis:
capture stage must sustain recvmsg+verdict-sendmsg pair rate ≥ line
rate (~358 Kpps scale ref); worker adjudication ≥ same; TUN stage ≥
20% of line rate. **80% throughput floor** = all three stages
simultaneously sustain 0.8× baseline useful-delivered with the
above mix (any stage saturating first identifies the binding
constraint — the floor is a rate claim, not serialized-latency
addition). **250 µs p99** = 100 µs flush cap + ≤10 µs verdict pair +
≤10 µs TUN write + 130 µs p99 scheduling/backlog allowance (stated
decomposition; the 13× multiplier on the pair is the tail allowance,
gate-confirmed or killed). Baselines re-measured same-box same-day;
numbers ratified or plan dies.

Enforcement ([P] pass today): T1 deny (revert: rule deletion). T2
permit incl. REINJECT wire-verified mutation + TTL pin + mark
restore + reorder-bound sub-case. T3 per-VRF + post-TUN empty-chain
assertions. T4 app/port deny. T5 host-bound both verdicts + match-set
lifecycle. T6 fragments incl. split batches, non-first rule, v6
overlap-drop, dedup, ICMP-own-flow. T7 isolation. T8 saturation +
recovery. T9 bring-up refusal ⇒ tunnel down. T10 recreate/move/
demotion orderly+abrupt; unresolvable REFUSED; commit-point
linearization per disposition (old cancellation semantic struck).
T11 no-recirculation + per-phase once/at-most-once. T12[P] armed
paths + `oif == stN` + exact-rule-set scope pin. T13 advisory per
phase + #8276 updates. T14 per-phase per-cell (incl.
shadow-unavailable + shadow ACCEPT-with-divergence). T15 once-ness
under flood + flush scheduling. T16 revocation incl. flip-drain +
quarantine (shadow sessions never publish). T17 verdict-issue fence
(renumbered; old semantic struck). T18[P] aliases + unowned `st5`.
T19 flush histogram under contention. T20 GRO/jumbo/over-TUN-MTU
refused-counted. T21 deny parity. T22 floors per derivation. New:
quarantine-violation (stale-epoch verdict refused); rule-swap
atomicity (no open window under rotation fuzz); route-flap drop;
uncertain-submission reconciliation converges to dropped.

## 9. Out of scope

Userspace ESP decryption. Policy-based IPsec. Unconditional armed
chains. AF_XDP on xfrmi. AF_PACKET entirely. WireGuard kernel-path
residual; #8279. Selector/`allowed-ips`-as-policy. Shape-B outbound
under permit-all. Flowtables. Cross-node sync; standby adjudication.
Re-tuning the scale. L4-mutation on non-first fragments
(DROP-and-count). Mutated host-bound (DROP-and-count). REINJECT
metadata residuals as topology-contained (conntrack fresh-flow view;
§4.5). Residual cross-wire reorder at class boundaries (bounded,
tested).

## 10. Open questions (each invites PLAN-KILL)

1. NFQUEUE per-packet API cost affordable at all? B rescues the wake
   only — third authoritative transport or B2 dead?
2. Flush-timer ownership under NAPI pressure — cap enforceable or
   fiction?
3. Generation primitive selection among pinned behaviors
   (non-blocking; N6-class).
4. Do the 25 `desc.len` counters enumerate — wider refactor ⇒ kill
   or re-scope?
5. Bounded-reassembly budget fit — which side gives; is
   drop-non-first acceptable, stated where?
6. Queue depth vs burst: fail-always avoidance within T22; plus queue
   *timeout* ownership (H5: 50 ms initial, gate-validated).
7. What pins the divert rule set — is T12's scope test sufficient as
   the ONLY guard?
8. Stage-rate assumptions (§8): if any stage misses its rate on
   cluster silicon, which degrades first — deeper batching, fewer
   tunnels, or dead plan?

## 11. Acceptance

- Both reviewers at PLAN-READY on this revision (or reported split),
  raw verdicts in `reviews/`.
- G1+G2 pass with per-core attribution; T22 derivation confirmed on
  silicon or plan killed; no capability-denial cited as pricing.
- Implementation PR (separate) carries the T-suite green on real
  traffic (enforcement/[P] split honored), no faked numbers,
  same-change advisory removal + #8276 updates.
