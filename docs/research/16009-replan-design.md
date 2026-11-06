# #16009 — architecture step-0 re-plan (revised: rank-1 shapes measured before any scope adoption)

- **Status:** design/research only. This revision recommends one route
  for hostile three-seat review. It authorizes no code, no verifier run,
  no scope change, and no artifact generation. It does not amend the
  landed plan by itself: §6 is the exact scope-change wording a
  reviewer/owner must adopt to make the recommended route effective,
  and §7 names how that adoption is filed and worded so it cannot be
  mistaken for silent narrowing. The rank-1 measurements in §7 are a
  LATER authorized step under the verifier-fit budget; this revision
  runs none of them.
- **Inputs (all read for this document; no new measurement taken):**
  - `docs/research/16009-host-screen-plan.md` on master, especially §1
    (verified mechanism and the 11 arms), §2 item 2, §2.1, §2.2, §4.4,
    §5.5, §8, §9-K1, and §10 (S1–S6 and the conditional S7).
  - `docs/research/16009-verifier-fit-design.md`, especially §2 item 2,
    §3 (measured failure matrix), §7 (composite ranking), §8 (bounded
    prototype, exact order/cap, and the stop rule), and §9 (prescribed
    first order: V6-1 + V4-1 + TCP-1).
  - `docs/log/16009.md` in the dirty implementation worktree
    `wt-16009impl` (read-only here), especially the section
    “Rebased K1 isolation — 2026-11-06”, base
    `c10b3aa06445ca4e51e989d20fd90c95c84533c7`, and its Risk directive
    at :87-90.
  - The three PLAN-NEEDS-MAJOR reviews of the prior revision of this
    document (Sol `Sol16009Replan`, Kimi `Kimi16009Replan`, GLM
    `Glm16009Replan`, on #16009) and the parent correction accepting
    GLM's trigger finding (`issuecomment-6673271416`).
- **Trigger (corrected; this corrects the prior revision).** The
  verifier-fit §8 bounded sequence was **never executed**. Its
  predeclared shapes — V6-1/V6-2R/V6-3, V4-1..3, TCP-1..3, 9 isolated
  attempts plus up to 3 complete-object compositions plus 1
  confirmation, 13 runs in all — are **unmeasured** (0 of 9 isolated
  attempts, 0 of 3 compositions; the fit fold `f27d1173ad` already
  recorded “all candidate shapes remain unmeasured”). What failed
  pre-prototype were the diagnostic slices the fit document used as
  INPUT (§3.1): original-form observer/TLV/tiny+post-L4 shapes and
  their held variants. Those diagnostics motivated the fit design; they
  are not executions of it. Therefore §8's arm-stop readings apply only
  to the shapes actually measured, and **the only §8 stop clause that
  can honestly fire today is clause (iv)** — “the team proposes
  removing Q1/C23 coverage to make the count fit” — because that
  proposal is this document's own route (b). No other clause has fired:
  no predeclared shape has failed, the composition limit is unspent,
  and no override was consumed. Seats must not read this re-plan as
  “fitting is exhausted”; it is not.

  Two consequences follow, and this revision is built on both.
  **First, the gates are re-ordered (§7):** the rank-1 predeclared
  shapes V6-1 + V4-1 + TCP-1 — exactly the first order prescribed by
  fit §9 and fit §8 steps 2–4 — run under the ORIGINAL scope, spending
  at most 3 of the 13 authorized runs, BEFORE any G0 scope adoption.
  §6.1's Q1 removal is considered only after a rank-1 failure; it is
  adopted only if the pre-adoption G2 complete-object diagnostic meets
  the first-build K1 thresholds and the owner chooses route (b). A
  passing rank-1 shape is not a reason to reduce scope. This ordering
  is the parent preference recorded on #16009: these measurements are
  “cheap, pre-authorized, and decisive for both the stop question and
  route (b)'s premise.”
  **Second, the lane-log directive is addressed, not silently inverted:**
  `wt-16009impl/docs/log/16009.md:87-90` directs
  “Stop expansion; do not narrow or delete TCP coverage… rework and
  remeasure”. This revision honors that directive in its ordering —
  rework-and-remeasure (rank-1) comes first; narrowing (G0/§6.1) is
  reachable only after those measurements fail, and then only as the
  plan §9-K1 pre-negotiated, recorded, S7-backed act — never as the
  silent deletion the directive forbids. §8 item 2 states the evidence
  that would make the directive's sequence unnecessary.

---

## 1. Recommendation (one route)

**Recommend a staged decision, not immediate scope adoption.** First run
the three rank-1 predeclared shapes — V6-1, V4-1, TCP-1 — under the
ORIGINAL #16009 scope, in fit §9's order and within the existing 13-run
budget. If all three clear their isolated semantic/access/stack gates,
continue the original-scope bounded protocol; do not adopt §6.1 or file
S7 on the basis of this re-plan. If one or more fail, run the single
pre-adoption no-Q1 complete-object diagnostic in §7.1. Adopt route (b)
and §6.1 only if that first complete-object build meets the per-build
K1 thresholds (≤850,000, floor PASS, no override); otherwise do not spend
the scope reduction and return to architecture step 0 to compare
routes (a), (c), and (d) with the evidence in hand. No result here
licenses an unrecorded further narrowing.

This order repairs the previous recommendation's central defect. The
diagnostic slices in §3 are inputs to the verifier-fit design, not
executions of its bounded protocol; the predeclared shapes remain
unmeasured. The rank-1 attempts are cheap, pre-authorized, and decisive
for the stop question and route (b)'s premise. They are performed with
Q1 enabled, honoring the lane-log instruction to “Stop expansion; do
not narrow or delete TCP coverage… rework and remeasure.” The
pre-adoption no-Q1 object is a single, explicitly diagnostic experiment
within the existing complete-object budget, not an adopted scope,
acceptance run, or production candidate. It cannot authorize the reduced
scope by itself: the owner must still adopt §6.1 and file S7 at G0 before
any further reduced-scope work or landing.

The alternatives remain real decisions rather than straw men.
Redirect-to-worker (a), including bounded selective redirect, changes
the terminal-arm contract and requires a worker-health default plus
per-arm worker-path qualification; its feasibility is not measured
(§4.2). A geometry-first split (c) could isolate a strictly described
subset and might fit even though the measured first extraction shapes
did not; it would require an explicit scope change and successor
acceptance for every deferred predicate, not the plan's Q1-only S7
(§4.1). Plan-kill (d) is an available outcome if the evidence rejects
shim screening, not a claim that the defect itself is fixed (§4.3).
The pre-adoption diagnostic distinguishes route (b) from those
alternatives; no prior measurement priced them.

If route (b) is supported by the ordered evidence and selected, its
scope act is exact and explicit: remove only Q1 from #16009, transfer
only the Q1 artifacts enumerated in §7.2, and file S7 concurrently
before any further reduced-scope work. #16009 then claims only the
retained core in §5. If the diagnostic does not support route (b), the
fallback is §7.4; it is not permissible to implement “(b) minus the
scope-change act,” because that would be silent narrowing.

---

## 2. What is not in dispute

1. The bypass is real and verified. `xdp_userspace_prog` →
   `try_xdp_userspace` returns `XDP_PASS` / `cpumap_or_pass` on terminal
   kernel-pass arms; those packets never reach the AF_XDP worker, so
   worker screen stage 10 never runs on them (landed plan §1, citing
   `userspace-xdp/src/lib.rs:612-618` and `:2138-2146`, worker entry
   `userspace-dp/src/screen/mod.rs:912`). Only LAND is replicated at the
   shim today (`land_gate`, `lib.rs:2605-2636`).
2. The 11 parsed-IP terminal kernel-pass arms are enumerated and
   anchored in the landed plan §1 (WG steer; early-filter multicast/
   broadcast; session-hit `PASS_TO_KERNEL`; session-miss NAT-external
   NDP; proxy-NDP; ICMP-to-interface-NAT local; session-miss local;
   interface-NAT tunnel; GRE-inner `PASS_TO_KERNEL`; binding-not-ready
   degraded local/control; ctrl-disabled local/control). The two
   earlier CPUMAP returns (L2 parse failure, non-adjudicated ingress)
   occur before a `ParsedPacket` exists and are outside any gate.
3. Transit is not part of the problem. Transit session-miss/redirect
   reaches the worker and is already screened there; screening it at the
   shim would double-screen and risk the wrong zone (plan §5.5/K4).
4. The structural invariants are not the dispute: `ParsedPacket` and
   `ExtWalk` gain zero fields, `MAX_EXT_HDRS` (=7) and walk
   advance/break rules are unchanged, and any route that requires
   widening either struct is reviving a shape already measured at the
   1,000,001 cap (plan §3; verifier-fit §2 item 2).
5. The budget rule is not the dispute: complete object ≤850,000
   processed instructions, floor PASS, `override_consumed: false`, no
   `XPF_SHIM_ALLOW_LOW_HEADROOM` waiver. Only a complete-object
   measurement is K1 evidence; slice numbers are diagnostics.

Any seat that disputes one of these five points is disputing the landed
plan, not this re-plan, and should say so against that document.

---

## 3. Verifier arithmetic grounded in the measured slices

### 3.1 The measured table (the only numbers this document uses)

All figures below are transcribed from `docs/log/16009.md`, section
“Rebased K1 isolation — 2026-11-06” (same generation command,
`XPF_SHIM_ALLOW_LOW_HEADROOM=0`; no override consumed in any run), and
cross-checked against verifier-fit §3's failure matrix. They are
reproduced here so this document is self-contained; if any figure
differs from the lane log, the lane log governs.

| Shape measured | Result | Processed insns / states |
|---|---|---:|
| Pristine baseline (base `c10b3aa064`) | PASS; 22.0787% headroom | 779,213 |
| Sink-only parser slice | PASS; 24.44% headroom | 755,620 |
| Full-delta diagnostic with gate (original variable-length Routing read; **not** a verifier-fit §8 composition) | REJECT `invalid access to packet, off=56 size=1`, `R1(id=0,off=56,r=56)`; 30,642 processed (diagnostic count, *not* a K1 count); 2,223 total states | 30,642 |
| No-gate full-delta diagnostic (same delta, all 11 call sites removed; **not** a verifier-fit §8 composition) | REJECT, same `off=56` class; earlier base `6c9098dcfb` | 30,223 |
| IPv6 observer slice (original Routing read) | REJECT `off=56 size=1`; 2,136 total states | 30,152 |
| IPv6 fixed three-byte-prefix variant | Access reject cleared; then REJECT at cap; 63,606 total states | 1,000,001 |
| IPv6 map-accumulating variant | REJECT at cap; 61,589 total states | 1,000,001 |
| IPv6 out-of-line callback variant | REJECT at cap; 61,135 total states | 1,000,001 |
| IPv6 generic-walker outline | Link failure (bpf-linker: unsupported stack arguments) | n/a |
| IPv4 TLV/options scan atop sink | REJECT `off=34 size=1`, `R3(id=0,off=34,r=34)`; 5,672 states | 101,057 |
| IPv4 static-dispatch checked-byte reader | REJECT `R3 tried to subtract pointer from scalar`; 5,673 states | 101,488 |
| IPv4 stack-copy variants (two) | REJECT `off=35 size=1` | 101,366 / 99,774 |
| IPv4 tiny-declared + post-L4 TCP-trip slice | REJECT: **528-byte combined stack across 3 calls** (limit 512); 47,384 total states | 775,418 |

Derived constants (arithmetic on the table, not new measurement):
cap = 1,000,000; landing ceiling = 850,000; floor = 15% headroom;
baseline slack to ceiling = 850,000 − 779,213 = **70,787** insns;
headroom fraction of baseline = (1,000,000 − 779,213)/1,000,000 =
22.0787% (matches the recorded figure); sink-only slack to ceiling =
850,000 − 755,620 = **94,380**.

The per-arm comparisons to the 850,000 ceiling are diagnostic only:
each 1,000,001 IPv6 cap-trigger run is at least 150,001 processed
instructions above the ceiling, so any shape that passes K1 must
reduce the observed count by at least that much; this is a censored
lower bound, not an estimate of the actual reduction needed. The TCP
slice stopped on stack at 775,418 processed instructions, a raw
74,582 below the ceiling, but that is not verified instruction
headroom or an instruction-budget pass. Its combined stack was
528 bytes, 16 above the 512-byte limit. IPv4's access-reject counts
(99,774–101,488) do not establish a usable instruction cost or
remaining budget for a legal access shape.

### 3.2 What the arithmetic does and does not prove

The honest reading requires three distinctions that hostile reviewers
should hold this document to, because each one kills a tempting
overclaim.

**Censored counts are not costs.** Every `1,000,001` figure is a cap
trigger: the verifier stopped after the processed-instruction limit,
so the complete count for a successful verification is unknown.
Likewise, the
`off=56/off=34/off=35` rejects (30,152–101,488 processed) are
*early-exit* diagnostics: the verifier refused one access and stopped.
These counts do not price the legal version of a repaired shape; its
complete-object result is unknown, as the fixed-prefix IPv6 variant
demonstrates by changing both the access shape and the result (cap at
1,000,001). Therefore no slice number in the table may be used as “this
arm costs N instructions”. It may be used only as a signature: this
shape fails, in this way, before or at the cap.

**Slice counts are not additive.** The sink-only slice (755,620)
verifies *below* the pristine baseline (779,213) by 23,593 insns. A
strictly additive model cannot predict that result: adding a checked
per-CPU scratch write/read mechanism coincided with a lower measured
total. That is direct evidence that source-level per-feature costs
cannot be summed to predict this object's processed-instruction count.
The result is consistent with the verifier-state-merging rationale
documented for the existing scratch-laundering precedent (landed plan
§5.1: direct consumption rejected at 1,000,001, laundered form verifies),
but this pair of measurements does not isolate that mechanism.
Consequence: “baseline + IPv4 delta + IPv6 delta + TCP delta” is not a
computable estimate of the complete object, and any route whose case
rests on such a sum is resting on a model this repository's measurements
do not support. The only number that decides K1 is a complete-object
measurement.

**States, instructions, and stack are separate constraints.** The
fixed-prefix IPv6 variant reached the instruction cap with 63,606 total
states. The TCP slice stopped on its 528-byte combined stack failure
after processing 775,418 instructions; its raw difference from the
850,000 ceiling is 74,582, but the failed run does not establish a
K1 instruction pass or available headroom. Its combined stack exceeds
the 512-byte limit by 16 bytes. Packet-access legality, explored-state/
instruction budget, and per-chain stack are therefore distinct
constraints: a shape can satisfy two and fail the third. Packet-access
rejects also report partial processed counts, so their lower counts
cannot be compared as instruction passes.

### 3.3 Per-arm reading

- **Sink (scratch mechanism): alive.** The one unambiguously surviving
  component. A checked per-CPU packed-word write/read is not by itself
  the blocker (verifier-fit §3 F1 conclusion). Every route below may
  assume the sink exists; none may assume more than that.
- **IPv6 observer arm: the measured diagnostics failed, but the
  predeclared candidates are not exhausted.** Four diagnostic forms
  failed — dynamic read (access), fixed prefix (cap), map accumulation
  (cap), out-of-line callback (cap) — plus a link failure for the
  outlined walker. These are not the verifier-fit §8 rank-1 V6-1
  attempt. V6-2R and V6-3 retain the checked routing-type read, so they
  cannot be counted as access fixes for that rejection; §4 establishes
  no metadata-only shortcut because `ExtWalk` carries neither routing
  type nor fragment count and has no reserved encodings. V6-1 remains
  explicitly unmeasured. Do not call the IPv6 arm exhausted or claim
  the §8 stop rule fired from these diagnostics.
- **IPv4 TLV/options arm: measured diagnostics failed; V4-1 remains
  unmeasured.** The dynamic scan (`off=34`), static-dispatch checked
  reader (pointer-from-scalar), and two stack copies (`off=35`) reject
  at small counts (99,774–101,488). Those signatures do not establish
  that the distinct predeclared rank-1 V4-1 shape fails, nor do they
  establish that all three fit candidates were measured. No complete
  object with this fact is yet K1 evidence.
- **TCP (tiny-declared + post-L4 trips): the diagnostic slice failed
  stack, but TCP-1 remains unmeasured.** The measured diagnostic stopped
  on a combined 528-byte stack across three calls, 16 above the 512-byte
  limit, after 775,418 processed instructions. That partial count is
  not a completed instruction-budget pass or usable headroom. The lane
  log does not localize which frame caused the peak. TCP-1 (shortened
  live range) is the first predeclared attempt, not an already-failed
  variant; TCP-2/3 remain conditional candidates under fit §8. Do not
  infer a fix from “only 16 bytes over,” and do not infer fit exhaustion
  from this diagnostic.

### 3.4 What the surviving core would need (bounded, not estimated)

The instruction asks what the surviving core *needs*. The honest form
of that answer is a set of necessary conditions, because §3.2 shows a
point estimate would be fabricated:

1. A complete object containing sink + gate + surviving fact arms at
   all 11 call sites must measure ≤850,000 with floor PASS and
   `override_consumed: false`, confirmed by a second identical-source
   build (verifier-fit §8 step 6).
2. The IPv4 arm needs an access shape that is *legal*, which no
   measured shape yet is. Until one IPv4 shape clears packet access
   in isolation, no complete-object number including IPv4 options
   facts is meaningful — the complete candidate will reject at the
   access, at an uninterpretable count, exactly as the 30,642
   diagnostic did.
3. The IPv6 arm needs either a shape whose failure cause is localized
   (so a predeclared variant addresses that cause) or an explicit
   decision that routing-type/duplicate facts leave the shim (which
   is a scope change and must be named as one — see §6.3).
4. The TCP arm needs a measured per-function *and* combined-chain stack
   report ≤512 bytes for every frame and chain (verifier-fit §8
   requires both metrics; one does not stand in for the other).
5. Removing Q1 (route b) removes Q1's trip-bit computation and its
   mask intersection, but this document claims **no specific insn or
   stack saving** for that removal, because §3.2's non-additivity cuts
   both ways: removal could help less than hoped if state merging at
   the parser convergence dominates, and the tiny-declared /
   capture-unknown facts (which are *not* Q1) stay behind regardless.
   What route (b) buys is a *smaller surface to make legal and fit*,
   plus an honest claim boundary — not a computed budget.

Any reviewer who wants a number for the surviving core should require
the measurement protocol in §7, not a forecast in this document.

---

## 4. The four routes against the evidence

### 4.1 Route (c) first, because the evidence re-examines it (plan §2.2)

The landed plan rejected splitting #16009 into per-check issues because
it would “fragment one mechanism (one gate, one map, one ABI append)
into five landings that each re-pay the verifier measurement and the
map-wiring cost, and would let partial parity ship silently.” The
diagnostic record does not prove a geometry-first subset infeasible:
the isolated packet-access rejects and stack report concern measured
shapes, while the predeclared candidates and alternative compositions
remain unmeasured.

**Per-check issue splitting** still risks paying shared gate/map/ABI
costs repeatedly and shipping partial parity, but those are costs, not
proof that every split fails. **Geometry-first split** is a distinct,
bounded candidate: preserve only the independently specified POD
predicate, teardrop geometry, ICMP-fragment wire-protocol check, and
SYN-frag first-fragment check where their required fields are already
available. Explicitly defer IPv4 options, IPv6 route facts, parser-error
coverage, and any other non-included check to named successors. This
could avoid the currently unmeasured legal-access requirements for IPv4
TLVs and IPv6 Routing headers; its verifier cost, semantic boundary,
worker-oracle cells, and successor ownership have not been measured or
negotiated. A clean split would need an explicit scope amendment, exact
per-cell transfer/retention, successor issues filed before the parent
issue closes, and its own complete-object K1 gate. This is not
authorized or rejected by the current evidence.

The rank-1 original-scope measurements and the no-Q1 diagnostic do not
directly price that geometry-first design. If the diagnostic cannot
support route (b), step 0 must compare this candidate on equal evidence
with bounded selective redirect and plan-kill; do not infer its failure
from the first extraction shapes, and do not infer its feasibility from
their lower partial counts.

### 4.2 Route (a): redirect-to-worker for host-bound packets

**What it would have to mean.** “Redirect” must be specified before it
can be evaluated, because the word hides three different contracts:

- **R1 — redirect only traffic that would trip a screen.** Impossible
  as stated: tripping is what the shim cannot yet compute. A **bounded
  selective redirect** is a different candidate, not R1: for example,
  a cheap, explicitly tested classifier could redirect a superset such
  as packets with IPv4 options or IPv6 extension headers at selected
  terminal arms, leaving other traffic on the shim. That may avoid a
  particular illegal variable-length read, but it still requires
  proving the classifier is safe, defining false-positive traffic and
  worker-health behavior, preserving row/zone semantics, and evaluating
  each selected arm. Its packet-read legality, verifier cost, worker
  availability contract, and coverage boundary are unmeasured. It must
  be assessed as its own architecture, not dismissed as “impossible”
  because exact-trip prefiltering is unavailable.
- **R2 — redirect all parsed-IP traffic at the 11 terminal arms to the
  worker (AF_XDP/XSK or CPUMAP-to-worker), kernel-pass only what the
  worker (or a timeout/default) returns.** This is the broad proposal
  evaluated below.
- **R3 — redirect only on worker-healthy signal, kernel-pass when the
  worker is unhealthy.** This makes screening availability-dependent by
  design: precisely when the worker is down, malformed host-bound
  traffic passes unscreened. That re-opens the bypass under exactly
  the degraded conditions the arms exist for, and is rejected without
  further analysis.

**Terminal-arm contract breakage (R2).** The 11 arms are not one
contract; redirecting them uniformly breaks different promises per arm,
and the landed plan already flagged the general form: “local/control
availability would depend on worker health, including degraded and
ctrl-disabled paths where `pass_local_control` is intentional
(`lib.rs:1812-1816`)” (plan §2.1). Arm by arm, the consequences a
proponent must accept *in writing* are:

| Arm class | Contract redirect changes |
|---|---|
| WG steer | Kernel WireGuard termination becomes worker-latency- and worker-liveness-dependent; steer is a data-plane decision, not a screening decision. |
| Early-filter multicast / limited-broadcast | Screened nowhere today by the worker (policy extension, plan §2); redirect makes multicast host delivery worker-dependent and changes its availability semantics. |
| Session-hit `PASS_TO_KERNEL` | The fast path's reason to exist is avoiding the worker; redirect converts every session hit into a worker round trip and must re-decide what a session *means*. |
| Session-miss NDP / proxy-NDP / ICMP-to-interface-NAT | Neighbor-discovery liveness becomes conditional on worker scheduling; NDP failure modes are control-plane outages, not packet drops. |
| Session-miss local / interface-NAT tunnel / GRE-inner pass | Local delivery and tunnel termination inherit worker queueing; GRE-inner additionally double-handles decapsulation ownership (outer redirect vs inner classification, cf. S5). |
| Binding-not-ready degraded local/control; ctrl-disabled `PassLocalControl` | These arms exist *so that* local/control traffic survives worker/binding failure. Redirect inverts them: the degraded fallback would depend on the component whose absence defines the degraded state. This is the single hardest break and the reason `pass_local_control` is deliberate, not incidental. |

**Worker-health dependence.** Under R2, host-bound reachability at all
11 arms becomes a function of worker liveness, XSK binding readiness,
queue capacity, and worker backpressure policy (drop? pass? queue
timeout?). Each of those needs a specified, tested answer, including:
worker process death after shim load; binding-not-ready at boot (the
arm whose name is that state); ctrl-disabled operation (an operator
*chose* no worker adjudication); and overload (the exact condition —
host-bound flood — under which LAND/malformed screens matter most).
A redirect design that drops on worker-absence fails closed against
*all* local/control traffic (an availability incident); one that
passes on worker-absence is R3 and re-opens the bypass. There is no
third default. This dilemma is structural, not an implementation
detail, and it is the reason the landed plan classified redirect as “a
possible re-plan if K1 kills this shape, not an in-scope fallback”.

**Screening-semantics mismatch.** Redirect also does not deliver the
worker's verdicts unchanged: the worker's stateless screens run inside
a stage order (`LAND → TCP flags → fragment/route`, flow path
`mod.rs:912ff`) with flow/flowless asymmetry (the flowless twin runs no
TCP-flag screens, `mod.rs:1262-1276`), fragment-overlap arming gaps for
non-IPsec LocalDelivery (S1 exists precisely because redirect alone
does not close the overlap acceptance; plan §2.1), and zone semantics
(raw vs claimed, S6) that the terminal arms currently resolve
differently. A redirect proponent must therefore specify, per arm,
which worker path the packet lands on and why its verdict equals the
screening intent — a new qualification boundary between transit and
local that does not exist today.

**Verifier and architecture comparison for (a).** The measured table
does not price redirect, whether broad or selective. A selective design
could reduce the number of shim-side packet reads and redirect only a
classifier-defined superset, but its classifier still must be verifier
legal and its false-positive traffic inherits the worker availability
contract. Before ranking it against route (b), specify the selected
arms, exact prefilter inputs, worker path, health/overload default,
transit-vs-local behavior, and BPF/worker acceptance; then measure the
complete object. Broad redirect adds every terminal arm and the same
availability obligation. No measured slice establishes either design
as “free,” infeasible, or cheaper. Neither is the current recommendation,
but both remain viable step-0 candidates if the ordered evidence does
not support (b).

### 4.3 Route (d): PLAN-KILL the shim-screen approach, with successors

Plan-kill is the honest route if the approach — “replicate worker
stateless predicates at terminal kernel-PASS arms” — is itself shown
wrong or not worth its measured constraints. The current diagnostics do
not establish that: they reject particular extraction shapes, while
the verifier-fit rank-1 candidates were not run. Nor does “PLAN-KILL”
close the user-visible defect. It rejects this proposed design and
requires named successor ownership for the still-open bypass and
acceptance; it cannot be recorded as a fix or used to close #16009.

If the rank-1 attempts and no-Q1 diagnostic fail to support the
recommended route, route (d) remains a genuine choice alongside
selective redirect and geometry-first split. A plan-kill decision must
state which security requirement is reassigned to which successor,
who owns it, and which tests establish eventual disposition. It is not
evidenced merely by the three diagnostic signatures, nor can the
preserved review negotiation be treated as a substitute for successor
filing.

### 4.4 Why (b) survives the same scrutiny

Route (b) remains a conditional candidate, not the conclusion of the
measurements already in hand:

1. **It removes a semantically separable family.** Q1's four checks are
   independent mask bits by design (plan §4.4: bits 5–8, “No shared
   TCP-family bit is permitted”), and their C23 oracle matrix is
   separable from the geometry/source-route/parse-error facts. This
   supports a clean transfer boundary, not a claim that Q1 removal
   improves the verifier result.
2. **It is the only reduction already pre-negotiated.** Plan §9-K1 and
   §10 specify S7 and the transfer of C23's Q1 matrix. That makes this
   reduction easier to record honestly than inventing a new scope
   amendment; it does not prove that a no-Q1 object passes or that other
   candidates are worse.
3. **Its premise is falsifiable before adoption.** Rank-1 shapes run
   under original scope; a failure makes the diagnostic gate reachable.
   The no-Q1 complete-object diagnostic asks whether a full retained-core
   object can meet the per-build K1 thresholds; it does not estimate an
   instruction saving or establish final K1. A diagnostic rejection
   means route (b) has no demonstrated viable object and cannot be
   adopted. A pass is evidence for the route, but not K1 acceptance or
   permission to land: G0, the identical-source confirmation, and
   Class-R remain required.
4. **It preserves terminal-arm behavior.** If selected, all 11 arms,
   zone resolution, degraded/ctrl-disabled behavior, and the worker's
   role remain unchanged. The cost is explicit: until S7 passes,
   host-bound kernel-PASS traffic is not screened for SYN+FIN, no-flag,
   FIN-without-ACK, or WinNuke at the shim. Those Q1 checks are never
   counted as #16009 parity during that interval.

Route (b) wins only if the ordered evidence and the owner's explicit
scope decision support it. If the diagnostic does not demonstrate a
Q1-related improvement, the document does not recommend spending the
single pre-negotiated reduction; step 0 compares the alternatives.

---

## 5. Retained core if route (b) is explicitly adopted

This is the exact claim boundary only after the §7 pre-adoption gates
support route (b), the owner records §6.1, and S7 is filed. Until then,
the original scope remains governing; rank-1 work runs with Q1 intact.

Retained in #16009:

1. Ping-of-death geometry; teardrop *geometry* only (C1 proves geometry,
   never overlap; overlap remains S1).
2. ICMP-fragment (wire protocol); SYN on a first fragment
   (SYN-frag); the worker's screen-state-gated IPv4 tiny-first-fragment
   flags-unknown error. Tiny-declared and capture-unknown are separate
   facts; the capture-unknown fact and its pointer-valued-end witness
   remain in #16009.
3. Source-route: IPv4 LSRR/SSRR and IPv6 Routing type 0/1, subject to
   finding a legal extraction shape. The Q1 cut does not fix the
   `off=34/off=56` access rejects.
4. Screen-state-gated fail-closed extraction errors: malformed IPv4
   options and a second readable non-atomic IPv6 Fragment header.
5. The mechanism: one outlined gate at all 11 terminal arms only,
   scratch-laundered packed word, raw-ingress `u16` zone-mask map,
   append-only aggregate `host_screen_drop`/`host_screen_alarm`
   (reasons 21/22), and zero widening of `ParsedPacket`/`ExtWalk`.

Explicitly not claimed: true fragment overlap (S1), port-scan/IP-sweep
(S2), SYN-cookie semantics (S3), zone/reason event and counter fidelity
(S4), GRE-inner screening (S5), claimed-zone terminal-pass parity (S6),
and — only if route (b) is adopted — the Q1 family transferred to S7.
Flood rate meters remain nft's, not the shim's.

Removing Q1 does not make the retained core fit. The IPv4 and IPv6
facts still need legal access shapes; the TCP stack report includes
tiny-declared work that remains. The rank-1 and no-Q1 diagnostic gates,
not a point estimate or the route label, decide whether this scope is
worth adopting.

---

## 6. Exact scope-change wording for route (b)

This wording is proposed only if the §7 rank-1 and pre-adoption
diagnostic gates support route (b), and the owner selects it after
three-seat review. “Adopting route (b)” means: (i) the #16009 issue
body (or its governing scope comment) is amended by inserting §6.1;
(ii) the landed plan's §2 item 6, §4.4 decision, and §9-K1 are
annotated as superseded to the extent stated in §6.1 (the plan file
itself is edited only through the normal reviewed-docs process); and
(iii) S7 is filed with §6.2's title and exact transferred acceptance
in the same act. No other scope change is authorized here.

> **Conditional scope change (only after the §7 gates pass and the owner
> selects route (b)):** #16009 no longer includes the Q1 TCP-flag family
> — SYN+FIN, no-flag, FIN-without-ACK, and WinNuke — on the shim
> kernel-PASS path. The four predicates, their independent profile-mask
> bits (bits 5–8), and only their acceptance artifacts listed as
> “transferred” in §7.2 are transferred to successor S7,
> `shim: retain independent TCP-flag screen family if #16009 verifier
> ceiling rejects Q1`. Until S7 passes, #16009 MUST NOT be described as
> providing, and its tests MUST NOT claim, host-bound Q1 screen parity.
> The IPv4 tiny-declared and capture-unknown facts, SYN-frag, and all
> non-Q1 portions of C22/C23 remain in #16009. The Q1-only profile's
> zero-core-mask row-presence witness and row-presence-gated extractor
> error drops also remain in #16009; they are not Q1 screen coverage.
> All other #16009 scope (geometry, ICMP-fragment, source-route, gated
> extraction errors, all 11 terminal arms, reasons 21/22) is unchanged.
> This is a recorded coverage reduction, not a claim that the original
> verifier-fit §8 sequence ran or exhausted its candidates. It is
> considered only after the original-scope rank-1 attempts and the
> pre-adoption no-Q1 complete-object diagnostic specified in §7.

### 6.2 S7 filing (title and acceptance, transferred not paraphrased)

- **Title (exact, from landed plan §10):** `shim: retain independent TCP-flag screen family if #16009 verifier ceiling rejects Q1`
- **Owner (from plan §10):** userspace-xdp shim plus Go mask/ABI
  maintainers.
- **Acceptance (transferred artifacts only):** restore the four
  independent Q1 trip predicates and profile-mask bits 5–8; reinstate
  the Go-builder Q1-mask/16-profile acceptance; and pass the Q1-only
  acceptance components explicitly transferred in §7.2: the C22
  no-flag-only leg (not its capture/declared facts or syn-frag-only
  leg), C23's 16 masks × 4 Q1 packets × IPv4/IPv6 = 128 worker-oracle
  outcomes (not C23's SYN-frag checks), C26's SYN+FIN drop assertion
  on session-hit PASS, and C35's SYN+FIN alarm assertion. Restore Q1
  bits in conservative emitted rows as part of S7. S7 owns exactly
  these Q1 artifacts; it does not own retained capture-unknown,
  SYN-frag, core-mask, row-presence, or extractor-error coverage.
  Do not report transferred checks as completed by #16009. S7's
  complete object must independently satisfy K1 (≤850,000, floor PASS,
  override false, identical-source confirmation).

### 6.3 What §6 deliberately does not do

This scope-change proposal does not transfer source-route,
malformed-options, duplicate-Fragment, tiny-declared, capture-unknown,
SYN-frag, or the zero-core-mask row-presence witness, even though some
extraction shapes have not yet cleared verifier access. Those retained
predicates stay in scope with their fitting problem named as open
(§3.4). Route (b) is exactly a Q1-only reduction. If the owners or
reviewers conclude that other facts must leave #16009, reject route (b)
and compare geometry-first split, selective redirect, or plan-kill
openly; do not extend §6.1 by analogy or silently assign new artifacts
to S7.

---

## 7. Gate plan and kill criteria for the chosen route

No step below is authorized by this document; the sequence states what
the three seats are being asked to approve, in order, so that approval
has a definite object. “Verifier run” everywhere means the exact pinned
command of verifier-fit §8 with `XPF_SHIM_ALLOW_LOW_HEADROOM=0`, in
detached scratch worktrees, never installing a generated object.

### 7.1 Gates (in execution order)

No run is authorized by this research revision itself. After hostile review
authorizes the sequence, use the pinned command in verifier-fit §8 with
`XPF_SHIM_ALLOW_LOW_HEADROOM=0`, detached scratch worktrees, and no
installation. Diagnostic builds remain diagnostics and never establish
production or acceptance results.

1. **G1 — original-scope rank-1 attempts (first, before any G0).** Run
   the first three predeclared isolated shapes, under the ORIGINAL
   #16009 scope with all Q1 checks intact, in fit §9 / §8 order:
   V6-1, then V4-1, then TCP-1. This is at most 3 of the existing 13
   authorized runs; run each only once, with the fit §8 host corpus
   before its verifier attempt. Record each exact rejection layer,
   signature, instruction/state count, link result, and for TCP both
   per-function and combined-chain stack. TCP-1 passes its stack gate
   only when every frame and the combined chain are each ≤512 bytes.
   Any packet-access rejection, 1,000,001 cap rejection, link failure,
   or per-frame/combined stack value >512 is a measured failure for
   that shape, not a pass and not by itself proof that the whole arm's
   remaining predeclared shapes were exhausted. If all three rank-1
   shapes pass their gates, do not adopt §6.1 or file S7; continue the
   original-scope verifier-fit §8 protocol with Q1 intact.
2. **G2 — pre-adoption no-Q1 complete-object diagnostic.** This gate is
   reachable before G0 only if at least one of the three G1 rank-1
   attempts fails and the owner is considering route (b). If all three
   pass, continue the original-scope verifier-fit protocol; a later
   full-scope failure without a G1 rank-1 failure is a return-to-step-0
   decision, not permission to adopt §6.1 under this re-plan. Build one
   diagnostic complete object with only Q1 computation/mask coverage
   removed; retain all other required facts, gate, map, mirrors, and all
   11 terminal arms. Use the exact rank-1 shape set from G1; do not
   invent or silently substitute a shape. Record the complete verifier
   outcome and rejection layer, using at most one of fit §8's three
   complete-object compositions (not a 14th run). This pre-adoption
   object is the narrow exception to the no-reduced-scope-work rule: it
   is a scratch diagnostic only, not a scope act, acceptance run,
   Class-R result, or landing candidate. Route (b) is supported only
   if this complete no-Q1 object meets the first-build K1 thresholds
   (≤850,000, floor PASS, `override_consumed: false`). If it rejects
   at any layer, including packet access, cap, link, or stack, **do not
   adopt §6.1**: route (b) has not demonstrated a viable complete object
   and §7.4 applies.
   This makes the no-Q1 premise falsifiable before scope adoption.
3. **G0 — scope adoption (only after G2 passes and the owner chooses
   route (b)).** After three-seat convergence, amend the issue/scope
   record with §6.1 and file S7 with §6.2's exact transferred
   acceptance in the same act. Do this before any further reduced-scope
   work, confirmation build, Class-R cell, or production landing. If
   G1's three attempts all passed, G2 is not a reason to narrow; the
   original-scope protocol continues and G0 does not occur.
4. **G3 — identical-source K1 confirmation.** The passing G2 object is
   only the first complete-object measurement. After G0, rebuild the
   identical source hashes once; it must again report ≤850,000, floor
   PASS, and `override_consumed: false`. Any source change invalidates
   the pair and must stay within fit §8's existing composition and
   confirmation caps. A result in 830,000–850,000 also requires the
   plan's written headroom-recovery follow-up. Slice or partial-object
   numbers are never K1 evidence.
5. **G4 — Class-R and semantic acceptance.** Only after both complete
   K1 measurements pass, run the retained host/parser corpus and Go
   builder cells described after the matrix, all retained/replaced
   `BPF_PROG_TEST_RUN` cells in the matrix, and the dual-stack smoke in
   the Class-R VM lane (`make vm-test-root`). The lane log says these
   cells were NOT-EXAMINED on the workstation. Transferred Q1 assertions
   must be absent from #16009 acceptance because they belong to S7, not
   reported as passing or failing there.

### 7.2 Cell-by-cell acceptance disposition

“Retained” means #16009 still requires the assertion as written in
substance. “Replaced” means preserve the branch/arm or core acceptance
but change a Q1-specific trigger to an in-scope trigger. “Transferred”
means only the stated Q1 assertion moves to S7; any other listed
subassertion stays in #16009.

| Cell | #16009 disposition after route (b) |
|---|---|
| C1 | **Retained:** teardrop geometry and its transit control; geometry only, never overlap. |
| C2 | **Retained:** LSRR enabled drop and disabled pass. |
| C3 | **Retained:** wire-protocol ICMP-fragment behavior and UDP control. |
| C4 | **Retained:** POD extent strictly greater than 65,535 drops; equality passes. |
| C5 | **Retained:** SYN-frag first-fragment drop and whole-SYN control. |
| C6 | **Retained, fixture updated:** tiny-declared/error row-presence behavior, using builder-valid zero-mask and core-only conservative rows; Q1 bits are absent from the conservative row. |
| C7 | **Retained:** IPv6 RH0 drop and RH2 pass. |
| C8 | **Retained:** legal short last-fragment pass guard. |
| C9 | **Retained, trigger unchanged:** a core geometry trip under alarm-only disposition passes, increments alarm, and does not increment drop. |
| C10 | **Retained:** unresolved raw-zone geometry uses the explicit fail-closed policy; no tiny/error-only drop is claimed for unresolved zone. |
| C11 | **Retained:** LAND owns the LAND drop, not host-screen counters. |
| C12 | **Retained:** clean local TCP ACK has no screen counter. |
| C13 | **Retained:** selected binding-not-ready local/control arm screens C1; false/transit branch remains unchanged. |
| C14 | **Retained:** selected ctrl-disabled `PassLocalControl` arm screens C1; non-adjudicated input remains its existing drop. |
| C15 | **Retained:** session `PASS_TO_KERNEL` with C1 has exactly one shim drop; no worker result is asserted. |
| C16 | **Retained:** one atomic IPv6 Fragment header passes. |
| C17 | **Retained:** `[atomic][non-atomic offset>0]` governing-header selection; no duplicate-header claim. |
| C18 | **Retained:** v6 tiny first-fragment remains an earlier `L3 PARSE_FAIL` control, not host-screen parity. |
| C19 | **Retained:** zero-payload-length remains an earlier `L3 PARSE_FAIL` control, not host-screen parity. |
| C20 | **Retained, fixtures updated:** malformed IPv4 TLV before/after valid LSRR drops on row presence. Use the zero-mask flood-only row, a core-only `BadNumericUnresolved` row, and the separate Q1-only zero-core-mask row witness below. |
| C21 | **Retained, fixtures updated:** second readable non-atomic Fragment notification/drop and exact duplicate chain; use builder-valid zero-mask, core-only conservative, and Q1-only zero-core-mask row fixtures. |
| C22 | **Split:** retain the actual-capture fact from `data_end.checked_sub(data)`, both-direction pointer-valued-end parser witness, and `tcp_flags_capture_unknown=1`; keep the selected session-miss-local BPF pass with an actual pointer-valued end and syn-frag-only row, plus its host/worker control. Transfer only the no-flag-only Q1 assertion to S7; that leg remains a disclosed divergence, never parity. Keep `tiny_declared_unknown=0` independent. |
| C23 | **Split:** transfer the Q1-only 16 masks × 4 Q1 shapes × IPv4/IPv6 = 128 worker-oracle outcomes and independent-bit assertions to S7. Retain the SYN-frag selected known first-fragment assertion and its relevant whole-SYN, first-fragment-ACK, and non-first-SYN-sentinel controls in #16009. The WinNuke-specific URG\|ACK-to-139 test transfers; it is not retained as a core check. |
| C24 | **Retained:** WG selected-pass LSRR drop and WG-admission/transit control. |
| C25 | **Retained:** early-filter multicast/broadcast selected-pass policy-extension cells and non-selected controls; not worker parity. |
| C26 | **Replaced + split:** keep the session-hit `PASS_TO_KERNEL` arm and non-selected/transit control in #16009, but replace SYN+FIN with an in-scope LSRR or geometry trigger and assert that core drop. Transfer only the SYN+FIN selected-pass drop assertion to S7. |
| C27 | **Retained:** NAT-external NDP selected pass, complete-fragment predicates, and hop-limit control. |
| C28 | **Retained:** proxy-NDP selected pass and disjoint-map/hop-limit control. |
| C29 | **Retained:** ICMP-to-interface-NAT selected local pass with LSRR and transit control. |
| C30 | **Retained:** session-miss local selected pass with C1/LSRR and link-local exact-local/non-owned controls. |
| C31 | **Retained:** interface-NAT tunnel selected pass with whole ESP+LSRR and transit control. |
| C32 | **Retained:** GRE-inner selected pass on outer LSRR and redirect controls; inner parity remains S5. |
| C33 | **Retained:** binding-not-ready selected local/control drop and transit-false accounting control. |
| C34 | **Retained:** ctrl-disabled selected `PassLocalControl` drop and transit/non-adjudicated controls. |
| C35 | **Replaced + split:** retain `BadNumericUnresolved` alarm-bit preservation and alarm-without-drop for an ordinary **core** trip (use LSRR or geometry), plus parse-error drop-on-row-presence despite alarm. Transfer only the SYN+FIN alarm assertion to S7. |

**Host corpus and Go acceptance.** Keep all host/parser corpus
assertions for retained checks above, including the absolute-pointer
C22 helper witness, independent capture-vs-declared facts, SYN-frag
tests, C20/C21 malformed/error rows, and the C23 SYN-frag controls.
Retain the plan's separate worker-stage assertion for an actually
worker-bound malformed twin: assert `batch.screen_drops` and the
per-reason counter where exposed; assert events only when the harness
observes the stream. It is not a worker result inferred from any BPF
test and is not transferred to S7. Transfer only Q1 predicate/oracle
cases, Q1 trip bits, and the C22/C23/C26/C35 Q1 subassertions explicitly
identified above. In Go, #16009 keeps builder coverage for all retained
core bits, map capacity, row presence, collision/nil cases, and
`AlarmWithoutDrop` for both defined-but-unresolved missing and inert
references; remove the 16-Q1-mask/boolean acceptance from #16009 and
assign exactly that Q1 mask acceptance to S7. `BadNumericUnresolved`
conservative rows in #16009 carry all in-scope core defaults but zero
Q1 bits. `AlarmWithoutDrop` still allows ordinary core trips to
alarm/pass; extractor errors still drop whenever a screen row exists,
regardless of alarm or ordinary mask.

**Required Q1-only profile row-presence witness (retained).** Add a
builder/BPF witness for a valid profile whose only configured checks
were Q1: after the route-(b) cut the Go builder MUST still emit a
present row with a zero core mask (and its correct alarm value), rather
than treating the row as absent. With that row present, C20 malformed
IPv4-options and C21 duplicate non-atomic-header extractor errors MUST
drop by row presence even though the ordinary core mask is zero; with
the row absent, neither error gets a special screen-state drop. This
proves preservation of the worker's row-presence gate without claiming
Q1 screening. It is a #16009 acceptance artifact, not S7 coverage.

**S7 owns exactly the transferred Q1 artifacts:** the four independent
predicates and bits 5–8; their Go mask/profile acceptance; the C23
128-outcome Q1 matrix; the C22 no-flag-only assertion; C26's original
SYN+FIN session-hit drop assertion; C35's original SYN+FIN alarm
assertion; and Q1 bits in emitted conservative rows. S7 does **not**
own C22 capture/declared facts, C23 SYN-frag checks/controls, SYN-frag,
the zero-core-mask row witness, core-only conservative rows, or
row-presence-gated extraction errors. Do not transfer entire C22/C23/
C26/C35 or all host/Go corpus wholesale.

### 7.3 Kill criteria and rank-1 failure handling

Criteria 1–3 and 5–6 below kill route (b). A G1 rank-1 failure is
instead an explicit input to G2; it is not itself proof of exhaustion
or a route-kill.

1. **Scope kill:** the owner will not adopt §6.1 after G2 passes, or
   will not file S7 concurrently. Route (b) without the explicit act is
   silent narrowing and is prohibited.
2. **Diagnostic kill:** the pre-adoption no-Q1 complete object rejects,
   fails the floor, exceeds 850,000, consumes an override, or cannot be
   built from the exact rank-1 shapes. Do not adopt §6.1; return to §7.4.
3. **Core/confirmation kill:** after G0, the identical-source G3 build
   fails any K1 condition. Consequence is §7.4, not a second scope
   reduction.
4. **Rank-1 arm-failure gate (not by itself a route-kill):** a G1 shape
   fails on any packet-access rejection, instruction-cap rejection
   (including 1,000,001), link failure, or stack failure. For TCP-1,
   either a per-function frame or the combined call-chain above 512
   bytes fails the gate; there is no TCP pass by checking only one
   stack metric. Record each failure layer and route it to G2. This
   does not claim that unattempted predeclared variants were measured;
   route (b) remains eligible only if the G2 complete-object diagnostic
   passes. If it fails, §7.4 applies.
5. **Contract kill:** fitting the retained core requires widening
   `ParsedPacket`/`ExtWalk`, changing `MAX_EXT_HDRS`/walk rules, gating
   transit, moving a LAND call site, or omitting any of 11 terminal
   arms. That is a new plan.
6. **Honesty kill:** any artifact describes #16009 as providing Q1
   parity before S7 passes, or attributes current diagnostics to an
   executed/exhausted verifier-fit §8 sequence. Correct the record
   before work resumes.

### 7.4 Bounded-work discipline and escalation

G1 uses at most three of verifier-fit §8's 13 runs. G2 is at most one
of its three complete-object compositions; G3 is the single final
identical-source confirmation. No rank-1 shape is retried unchanged,
no run is added beyond the 13-run cap (14 only for a changed-input
baseline as fit §8 permits), and no cosmetic or unregistered variants
are allowed. Any later full original-scope work follows fit §8 exactly,
including its rejection-specific variant rules. This research revision
itself spends no verifier budget and authorizes no run.

If G2 cannot be built or does not meet the first-build K1 thresholds,
do not adopt §6.1; return to architecture step 0. Compare bounded or
selective redirect (a), geometry-first split (c), and plan-kill (d)
using the measured evidence and requirements, not unmeasured cost
assumptions. If route (b) was formally adopted and its confirmation
later fails, return to step 0 with routes (a), (c), and (d) reopened;
carry §4.2's worker-health/per-arm table, exact successor ownership,
and the matrix in §7.2. After an adopted Q1-only reduction, no second
scope reduction is permitted by plan §9-K1.

---

## 8. Evidence that would change this recommendation

Each item states the evidence and the route it would select, so a seat
holding such evidence can overturn §1 by producing it.

1. **A measured complete object, under the *unreduced* scope, passing
   K1** (≤850,000, floor PASS, override false, identical-source
   confirmation, with a legal IPv4 access shape and an IPv6 shape
   whose failure cause was localized). → Route (b) is unnecessary;
   land the landed plan. This is the strongest possible falsifier and
   the one the authors would most welcome.
2. **All three G1 attempts pass under the original scope** without a
   complete-object result. → Do not adopt §6.1; continue the bounded
   original-scope fit protocol. A per-arm pass is not a complete K1
   pass, but it removes the asserted reason for adopting Q1 reduction.
3. **The pre-adoption no-Q1 complete-object diagnostic rejects** (for
   example at the same access/cap layer as the original-scope diagnostic
   inputs). → Route (b) has not demonstrated a viable complete object;
   do not adopt §6.1. Return to §7.4 and compare selective redirect,
   geometry-first split, and plan-kill rather than spending the
   pre-negotiated scope reduction.
4. **A bounded selective-redirect design** answers §4.2's worker-health,
   per-arm and false-positive questions in writing, specifies its
   classifier and coverage boundary, and has measured BPF/worker
   acceptance plus a complete-object result. → Re-score route (a)
   against route (b) and geometry-first split on the evidence, not on
   unpriced broad-redirect costs.
5. **Evidence the bypass is unreachable or already mitigated** on the
   11 arms (e.g., a proof that terminal-pass traffic is screened
   elsewhere, contradicting §2.1). → Plan-kill (d) may be correct only
   for the design; the defect stays open unless its acceptance is
   assigned to named, owned successors.
6. **A kernel/toolchain change** (verifier, bpf-linker, or pinned
   toolchain) legalizes a measured diagnostic shape or raises the
   effective state/stack envelope, demonstrated on the recorded failing
   slices. → Reassess the original-scope bounded protocol before any
   scope adoption.

Absence of these items is the current state of the record; the
recommendation in §1 is made on the record as it stands, and §3's
censoring/non-additivity limits (§3.2) apply to any new number brought
against it.

---

## 9. Risks of the recommended route (stated for the seats to attack)

- **Coverage-window risk.** Between #16009 landing under (b) and S7
  landing, the four Q1 predicates are unscreened on host-bound
  kernel-PASS traffic. Mitigation is procedural only: §6.1's wording,
  S7 filed concurrently (not “later”), and §7.3 kill criterion 6.
  A seat that judges the window unacceptable should reject (b) for
  that reason explicitly, rather than approve (b) and hope S7 is fast.
- **False-progress risk.** A passing pre-adoption no-Q1 diagnostic is
  only the first complete-object measurement, not a completed K1 gate
  or proof that Q1 can later be re-added. G3's identical-source build,
  the plan's written headroom follow-up if required, and S7's own K1
  gate remain mandatory. S7 inherits a bounded stop discipline, not
  just the matrix.
- **Scope-creep-by-analogy risk.** §6.3 addresses it: further removals
  require choosing a new route openly. Reviewers should treat any
  follow-on “small additional trim” proposal as a route change
  requiring the same three-seat process.
- **Residual-core risk.** The retained core still requires IPv4 options
  and IPv6 observer facts whose measured diagnostic signatures were
  adverse. The rank-1 candidates are unmeasured, and even a passing
  G2 diagnostic needs G3 confirmation. §7.4 pre-commits escalation so
  failure is a decision point, not drift into unplanned narrowing.

---

## Appendix A. Source map (so reviewers can check every load-bearing claim)

| Claim in this document | Source |
|---|---|
| Bypass mechanism; 11 arms; two pre-parse CPUMAP exclusions | Landed plan §1 |
| Narrowed core list; C1-is-geometry-only honesty | Landed plan §2 |
| Redirect changes terminal-arm contract; `pass_local_control` intentional (`lib.rs:1812-1816`) | Landed plan §2.1 |
| Anti-split argument (one gate/map/ABI; partial-parity risk) | Landed plan §2.2 |
| Q1 included, four independent bits 5–8, C23 128 outcomes | Landed plan §4.4 |
| Zero-widening invariant; scratch-laundering precedent (+298,128 / cap contrast) | Landed plan §5.1–§5.2; verifier-fit §2 items 1–2 |
| Gate placement (terminal arms only; transit excluded) | Landed plan §5.5, §9-K4 |
| K1 ceiling ≤850,000, floor PASS, no override; S7-on-Q1-removal prescription; “do not claim completion by narrowing again” | Landed plan §9-K1 |
| S1–S6 exact titles/owners; conditional S7 title/owner/acceptance | Landed plan §10 |
| Baseline 779,213; cap 1,000,000; 22.0787%; 70,787 slack | Verifier-fit §1/§3; lane log “Rebased K1 isolation” |
| Sink-only 755,620 PASS (24.44%; 94,380 slack) | Lane log, rebased isolation |
| All per-arm reject signatures and counts in §3.1 | Lane log, rebased isolation; verifier-fit §3 |
| V6-2R/V6-3 retain routing read, “cannot be counted as access fixes”; bounded budget; stop rule | Verifier-fit §8 |
| No metadata-only IPv6 shortcut (`ExtWalk` lacks routing type / fragment count) | Verifier-fit §4 |
| TCP 528-byte combined stack; both stack metrics required; pointer-valued-end witness | Verifier-fit §§6, 8; lane log |

## Appendix B. Non-goals of this document

No production code, no test change, no verifier or generation run, no
edit to the landed plan, the verifier-fit amendment, or the
implementation worktree, and no filing of S7 (filing is gate G0, an act
of the adopting owner, not of this research). Numbers herein are
transcriptions and arithmetic on the lane log (§3.1), offered for
review; the lane log remains the primary record.

*End of re-plan design.*
