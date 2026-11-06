# #16009 — architecture step-0 re-plan after the K1 stop rule fired

- **Status:** design/research only. This document recommends one route for
  hostile three-seat review. It authorizes no code, no verifier run, no
  scope change, and no artifact generation. It does not amend the landed
  plan by itself: §6 is the exact scope-change wording a reviewer/owner
  must adopt to make the recommended route effective, and §7 names how
  that adoption is filed and worded so it cannot be mistaken for silent
  narrowing.
- **Inputs (all read for this document; no new measurement taken):**
  - `docs/research/16009-host-screen-plan.md` on master, especially §1
    (verified mechanism and the 11 arms), §2.1, §2.2, §4.4, §5.5, §9-K1,
    and §10 (S1–S6 and the conditional S7).
  - `docs/research/16009-verifier-fit-design.md`, especially §3
    (measured failure matrix), §7 (composite ranking), and §8 (bounded
    prototype, exact order/cap, and the stop rule).
  - `docs/log/16009.md` in the dirty implementation worktree
    `wt-16009impl` (read-only here), especially the section
    “Rebased K1 isolation — 2026-11-06”, base
    `c10b3aa06445ca4e51e989d20fd90c95c84533c7`.
- **Trigger.** The verifier-fit §8 stop rule fired: the IPv6, IPv4, and
  TCP fact arms each failed independently in isolation (§3 below), so
  there is no complete-object candidate to assemble. The landed plan
  says the next step is then architecture step 0, and it names the
  alternatives a re-plan may consider: redirect-to-worker, the reviewed
  S7 route if Q1 is explicitly removed, per-check reconsideration, or
  plan-kill with successors. This document evaluates exactly those four
  routes and recommends one.

---

## 1. Recommendation (one route)

**Recommend route (b): an explicit, reviewed scope change that removes
Q1 — the four extra TCP-flag checks (SYN+FIN, no-flag, FIN-without-ACK,
WinNuke) — from #16009, filed together with the conditional successor
S7 in the exact form the landed plan already specifies (§6/§7), and a
K1 re-gate of the remaining core before any production landing.**

Nothing else in the landed plan changes. The scope change is removal
of spelled-out requirement text, not a weakened restatement of it:
#16009 would claim only the surviving core in §5 until S7 passes, and
the four Q1 predicates, their mask bits, and their 128-outcome matrix
move to S7 by transfer, not by deletion. If the remaining core still
fails K1, the landed plan's own escalation applies unchanged: return
to step 0 (where redirect-to-worker is reconsidered), and do not claim
completion by narrowing again.

Why this route, in one paragraph. It is the only route that is
(a) executable with the evidence already paid for, (b) honest about
what it gives up, and (c) survivable if it is wrong. Redirect-to-worker
(a) changes the terminal-arm contract for every local/control packet —
including the deliberate worker-independent `pass_local_control` paths
— while its instruction and availability costs are not priced by the
measured slices (§4.2). The per-check split (c) was argued against in
the landed plan §2.2 on one-mechanism and partial-parity grounds, and
the measured evidence weakens its premise rather than strengthening it:
the three failure signatures are three different mechanisms (access,
state cap, stack), not one shared verifier tax that splitting
amortizes (§4.3). Plan-kill (d) discards a verified, still-open bypass
(§2) whose pre-negotiated reduction the plan already specifies; killing
the approach now would re-open that negotiation from zero while the
bypass remains (§4.4). Route (b) is pre-authorized in form — the plan
§9-K1 and §10 already fix its wording, its successor, and its
acceptance — and is a bounded, predeclared experiment: measure the
reduced complete object after the scope change is recorded; that
pass/fail decides the next step without an unrecorded further contract
change.

This recommendation is conditional in exactly one place, stated here so
no seat has to infer it: route (b) is recommendable only if the
reviewing owner adopts §6 verbatim (or edits it in the open) and files
S7 concurrently. If either act is refused, route (b) is not available
and the fallback ordering in §8 applies — it is not permissible to
implement “(b) minus the scope-change act”, because that is the silent
narrowing the plan and the amendment both forbid.

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
   1,000,001 cap (plan §3; verifier-fit §2.2).
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
| Complete gated candidate (original variable-length Routing read) | REJECT `invalid access to packet, off=56 size=1`, `R1(id=0,off=56,r=56)`; 30,642 processed (a diagnostic count, *not* a K1 count); 2,223 total states | 30,642 |
| No-gate diagnostic (same delta, all 11 call sites removed) | REJECT, same `off=56` class; earlier base `6c9098dcfb` | 30,223 |
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

**States, not just instructions, constrain the candidate.** The
fixed-prefix IPv6 variant reached the instruction cap with 63,606 total
states. The TCP slice alone explored 47,384 total states while *passing*
on instructions (775,418) and failing only on stack. The binding
constraints observed are therefore three distinct resources —
packet-access legality, explored-state/instruction budget, and per-chain
stack (512-byte combined ceiling, measured at 528 across three calls) —
and a shape can be feasible on two and infeasible on the third. The TCP
slice is the clean example: it is the only failing slice whose
instruction count (775,418) is *below* baseline, yet it is dead because
528 > 512.

### 3.3 Per-arm reading

- **Sink (scratch mechanism): alive.** The one unambiguously surviving
  component. A checked per-CPU packed-word write/read is not by itself
  the blocker (verifier-fit §3 F1 conclusion). Every route below may
  assume the sink exists; none may assume more than that.
- **IPv6 observer arm: dead in every measured form.** Four distinct
  shapes failed — dynamic read (access), fixed prefix (cap), map
  accumulation (cap), out-of-line callback (cap) — plus a link failure
  for the outlined walker. Verifier-fit §8 adds the decisive structural
  point: V6-2R and V6-3 retain the checked routing-type read, so they
  “cannot be counted as access fixes”; and §4 establishes there is no
  metadata-only shortcut, because `ExtWalk` carries neither routing
  type nor fragment count and has no reserved encodings. The remaining
  unmeasured shapes (V6-1's stack accumulator inside the walk) are
  unproven, not promising: the burden of §8's stop rule is that an arm
  whose failure cause cannot be localized stops rather than guessing.
- **IPv4 TLV/options arm: dead in every measured form.** Dynamic scan
  (`off=34`), static-dispatch checked reader (pointer-from-scalar),
  and two stack copies (`off=35`) all reject *at small counts* (99,774–
  101,488) — i.e., this arm fails on access legality long before the
  instruction budget is even relevant. That signature matters for
  route choice: access rejects are shape properties, not budget
  properties. Making the object smaller elsewhere does not, by any
  measured mechanism, legalize a rejected access.
- **TCP (tiny-declared + post-L4 trips): dead as shaped, nearest to
  life.** It is the only arm that passes instructions (775,418 <
  779,213 baseline) and dies solely on 528/512 bytes across three
  calls — a 16-byte (3.125%) overage. Named remedies exist (TCP-1
  shorten live range; TCP-2 move Q1 derivation into the outlined
  gate; TCP-3 outlined scalar helper, verifier-fit §6), but none is
  measured, and the lane log explicitly does not localize which frame
  causes the peak. “Only 16 bytes over” is a fact; “therefore one
  attribute tweak fixes it” is folklore the amendment forbids
  (§8: “no attempt is repeated unless it is the predeclared final
  confirmation”; “no cosmetic retries”).

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

The landed plan rejected splitting #16009 into per-check issues
because it would “fragment one mechanism (one gate, one map, one ABI
append) into five landings that each re-pay the verifier measurement
and the map-wiring cost, and would let partial parity ship silently”.
The measured evidence changes the premises of that argument in one
respect and confirms it in the decisive respect.

*What changed:* the original anti-split argument assumed a shared cost
(one mechanism) that splitting would wastefully re-pay. The slices show
the three arms do not share a failure: they fail on three different
resources (§3.3). So “each split re-pays the same tax” is no longer
the right picture; the arms are more independent than the plan assumed.

*What did not change, and decides it:* independence of failure does not
create feasibility of parts. Each per-check successor would still have
to clear the *same* three gates on its own slice — a legal packet
access, a fitting state count, ≤512-byte chains — and zero of the three
arms currently clears its own gate in isolation. Splitting therefore
does not convert one infeasible object into several feasible ones; it
converts one infeasible object into several infeasible, separately
reviewed ones, each still owing the one gate/map/ABI mechanism the plan
refused to fragment, and each able to ship partial parity (the plan's
example: POD without ICMP-fragment) under its own issue number. The
evidence thus strengthens §2.2's conclusion by a new route: even
granting arm independence, there is no arm to land first. Route (c) is
rejected. Its one useful insight — that arms can be *decided*
independently — is preserved inside route (b), which removes exactly
one independently-decidable family (Q1, with independent mask bits by
design, plan §4.4) without fragmenting the mechanism.

### 4.2 Route (a): redirect-to-worker for host-bound packets

**What it would have to mean.** “Redirect” must be specified before it
can be evaluated, because the word hides three different contracts:

- **R1 — redirect only traffic that would trip a screen.** Impossible
  as stated: tripping is what the shim cannot yet compute (that is the
  whole problem). Any shim-side pre-filter cheap enough to fit is a
  coarser screen (e.g., “has IPv4 options”, “is a fragment”, “TCP”),
  which redirects a superset including clean traffic. The contract is
  then really R2 for that superset.
- **R2 — redirect all parsed-IP traffic at the 11 terminal arms to the
  worker (AF_XDP/XSK or CPUMAP-to-worker), kernel-pass only what the
  worker (or a timeout/default) returns.** This is the honest form of
  the proposal and the one evaluated below.
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

**Verifier arithmetic for (a).** Redirect is sometimes sold as “free”
because it deletes shim logic. The measured table does not support
“free”: the sink alone moved the total by −23,593 (§3.2), so deleting
the gate while adding redirect plumbing, health gating, and per-arm
re-qualification has an unpredictable sign. More importantly, (a) does
not retire the verifier problem, it relocates it: redirect decisions at
11 arms plus fail-safe behavior still live in the same ≤850,000 object,
now with availability-critical code paths that must be verified in both
worker-healthy and worker-absent configurations. No measured slice
prices this. Route (a) is therefore rejected *for now* — not as
unsound in principle, but as the largest contract change proposed to
solve a budget problem it does not measurably solve. §8 keeps it as
the named escalation if route (b)'s core also fails, which is where
the landed plan puts it.

### 4.3 Route (d): PLAN-KILL the shim-screen approach, with successors

Plan-kill is the honest route if the approach — “replicate worker
stateless predicates at terminal kernel-PASS arms” — is itself wrong.
The evidence does not show that. It shows three *fact-extraction*
shapes failing inside an approach whose plumbing (sink, gate placement,
zone resolution, counter ABI append) is unrefuted and whose bypass is
verified (§2.1). Two of the three arms fail on access legality, which
is a property of the extraction idiom, not of the decision to screen at
the shim; the third fails by 16 bytes of stack. Killing the approach
on this evidence would be killing it for the sins of its first
extraction shapes — while leaving the verified bypass open and forcing
successors to re-litigate the scope negotiation (which predicates,
which arms, which counters) that the landed plan already settled and
three seats already reviewed.

Plan-kill also has a bookkeeping cost its proponents must state: S1–S6
are written against the shim-screen scope and would need re-homing,
and the “successors carrying the security requirement” would, on the
evidence available, be routes (a), (b), or (c) renamed — since this
document's analysis is the successor analysis either way. Route (d) is
therefore rejected *as premature*, with an explicit kill criterion in
§7.4 that converts this re-plan to (d) if the surviving core also
fails: at that point two successive scope levels of the same approach
will have failed measurement, and “the approach is wrong for this
object” becomes the evidenced claim rather than a conjecture.

### 4.4 Why (b) survives the same scrutiny

Route (b) is not “the least bad option”; it has positive evidence the
others lack:

1. **It removes a semantically separable family.** Q1's four checks
   are independent mask bits by design (plan §4.4: bits 5–8, “No shared
   TCP-family bit is permitted”), with a self-contained acceptance
   artifact (C23: 16 masks × 4 packets × 2 families = 128 outcomes
   against the worker oracle). Removing them does not entangle the
   geometry/source-route/parse-error core, and restoring them is a
   mask-and-trip-bit addition, not a redesign.
2. **It is the only route the governing documents pre-negotiated.**
   Plan §9-K1 prescribes it verbatim if Q1 is removed (“file conditional
   successor S7 … transfer C23's … matrix … #16009 cannot claim those
   checks until S7 passes”), and §10 fixes S7's exact title, owner, and
   acceptance. The verifier-fit §8 stop rule repeats it (“the plan's
   reviewed S7 route if Q1 is explicitly removed”). A three-seat review
   of this document is therefore reviewing execution of an agreed
   contingency, not a novel scope invention.
3. **Its next measurement is interpretable.** A complete object without
   Q1 either passes K1 (the core is real and S7 becomes a bounded
   addition problem) or fails (the escalation in §7.4 fires with a
   clean conscience — no second silent narrowing is available, because
   §6 removes everything removable in one act).
4. **It does not touch the terminal-arm contract.** All 11 arms, zone
   resolution, degraded/ctrl-disabled behavior, and the worker's role
   are unchanged. If (b) is wrong, it is wrong as a verifier number,
   recoverable by S7 or by escalation — not as a production
   availability incident.

The cost of (b) must be stated as plainly as its virtues: until S7
lands, host-bound kernel-PASS traffic is **not** screened for SYN+FIN,
no-flag, FIN-without-ACK, or WinNuke at the shim, even though the
worker would screen the same packet on the flow path. That is a real,
named security-coverage reduction relative to the landed plan's
ambition — accepted temporarily, owned by S7, and never describable as
parity. §6's wording exists to make that sentence unavoidable wherever
#16009's scope is stated.

---

## 5. Surviving core under route (b) (what #16009 would still claim)

Unchanged from the landed plan §2 except Q1's removal:

1. Ping-of-death geometry; teardrop *geometry* only (with the plan's
   C1 honesty constraint: C1 proves geometry, never overlap; overlap
   remains S1).
2. ICMP-fragment (wire protocol); SYN on a first fragment (SYN-frag);
   the worker's screen-state-gated IPv4 tiny-first-fragment
   flags-unknown error — noting the tiny/capture-unknown distinction
   (plan §5.3) is *not* Q1 and does not leave with it.
3. Source-route: IPv4 LSRR/SSRR and IPv6 Routing type 0/1 — subject to
   §3.4 conditions 2–3: these facts currently have no measured legal
   extraction shape, so claiming them remains gated on finding one
   (this document does not pretend Q1 removal fixes `off=34/off=56`).
4. Screen-state-gated fail-closed extraction errors: malformed IPv4
   options; second readable non-atomic IPv6 Fragment header.
5. The mechanism: one outlined gate at the 11 terminal arms only,
   scratch-laundered packed word, raw-ingress `u16` zone-mask map,
   append-only aggregate `host_screen_drop`/`host_screen_alarm`
   (reasons 21/22), zero widening of `ParsedPacket`/`ExtWalk`.

Explicitly still not claimed (unchanged residue): true fragment
overlap (S1), port-scan/IP-sweep (S2), SYN-cookie semantics (S3),
zone/reason event and counter fidelity (S4), GRE-inner screening (S5),
claimed-zone terminal-pass parity (S6), plus — new under route (b) —
the Q1 family (S7). Flood rate meters remain nft's, not the shim's.

**A necessary warning against over-reading (b).** Removing Q1 does not
make the surviving core fit. The IPv4 and IPv6 arms fail on access and
cap for reasons independent of TCP (§3.3), and the TCP slice's stack
failure includes the tiny-declared computation that stays. Route (b)
is therefore a *scope honesty* act plus a *surface reduction*, sequenced
before further bounded fitting work — not a prediction that the core
passes K1. If the core then fails, §7.4 fires. Any seat asked to
approve (b) as “the fix that makes K1 pass” should reject that framing
and approve or reject (b) as what it is.

---

## 6. Exact scope-change wording for route (b)

The following text is proposed verbatim. “Adopting route (b)” means:
(i) the #16009 issue body (or its governing scope comment) is amended
by inserting §6.1; (ii) the landed plan's §2 item 6, §4.4 decision, and
§9-K1 are annotated as superseded *to the extent stated in §6.1* (the
plan file itself is edited only through the normal reviewed-docs
process — this re-plan does not edit it); and (iii) S7 is filed with
§6.2's title and acceptance in the same act. No other wording change
is authorized by this re-plan.

### 6.1 Scope-change text (for the #16009 record)

> **Scope change (adopted by the #16009 owner after three-seat review of
> `docs/research/16009-replan-design.md`):** #16009 no longer includes
> the Q1 TCP-flag family — SYN+FIN, no-flag, FIN-without-ACK, and
> WinNuke — on the shim kernel-PASS path. These four checks, their
> independent mask bits (profile-mask bits 5–8), and their acceptance
> matrix (C23: 16 masks × 4 packet shapes × IPv4/IPv6 = 128 outcomes
> against the worker oracle) are transferred to successor S7,
> `shim: retain independent TCP-flag screen family if #16009 verifier
> ceiling rejects Q1`. Until S7 passes, #16009 MUST NOT be described
> as providing, and its tests MUST NOT claim, host-bound TCP-flag
> screen parity. The IPv4 tiny-declared / capture-unknown facts and
> SYN-frag are not part of Q1 and remain in #16009's scope. All other
> #16009 scope (geometry, ICMP-fragment, source-route, gated
> extraction errors, the 11-arm gate, reasons 21/22) is unchanged.
> This change was made because the K1 stop rule fired (verifier-fit
> §8); it is a coverage reduction, recorded here, not a reinterpretation
> of the original requirement.

### 6.2 S7 filing (title and acceptance, transferred not paraphrased)

- **Title (exact, from landed plan §10):** `shim: retain independent TCP-flag screen family if #16009 verifier ceiling rejects Q1`
- **Owner (from plan §10):** userspace-xdp shim plus Go mask/ABI
  maintainers.
- **Acceptance (from plan §§9–10, binding):** restore the four
  independent Q1 bits and C23's 16-mask × 4-packet Q1 matrix for IPv4
  and IPv6 (128 outcomes), including mask bits and the worker oracle;
  do not report those checks as completed by #16009. This re-plan adds
  one acceptance clause the plan implies but does not state: S7's
  complete object must independently satisfy K1 (≤850,000, floor PASS,
  override false, identical-source confirmation), because S7 re-adds
  exactly the surface whose removal §6.1 records.

### 6.3 What §6 deliberately does not do

It does not remove source-route, malformed-options, duplicate-Fragment,
tiny-declared, or SYN-frag coverage, even though §3 shows the IPv4/IPv6
extraction shapes are currently dead. Those predicates stay in scope
with their fitting problem *named as open* (§3.4), because (i) there is
no pre-negotiated successor text for them equivalent to S7, and
inventing one inside this re-plan would exceed its mandate; and
(ii) removing them would cross the line from “defer one separable
family” to “abandon the screen”, which is route (d) and must be chosen
as route (d), in the open, if it is chosen. If the three seats conclude
the IPv6 routing/duplicate facts or the IPv4 options facts must also
leave #16009, the correct act is to reject route (b) and select (d)
with successors drafted for that purpose — not to extend §6.1 by
analogy.

---

## 7. Gate plan and kill criteria for the chosen route

No step below is authorized by this document; the sequence states what
the three seats are being asked to approve, in order, so that approval
has a definite object. “Verifier run” everywhere means the exact pinned
command of verifier-fit §8 with `XPF_SHIM_ALLOW_LOW_HEADROOM=0`, in
detached scratch worktrees, never installing a generated object.

### 7.1 Gates (in order; each gate stops the sequence on failure)

- **G0 — scope gate.** §6.1 adopted and S7 filed (§6.2) *before* any
  code or verifier work under the reduced scope. Hostile-review of this
  document converges (three seats) on route (b) or the sequence does
  not start. Evidence: the amended issue record and the S7 issue.
- **G1 — legality gate (per arm, isolated, at most the predeclared
  shapes).** For IPv4 and IPv6 respectively, an isolated slice must
  first *not reject on packet access*. An access reject stops that arm;
  analogy-driven fourth variants are prohibited (verifier-fit §8's cap
  discipline carries over: bounded attempts, no cosmetic retries).
  TCP's gate at this stage is a stack report (every frame and every
  combined chain ≤512 bytes) with Q1 trip computation absent and
  tiny/capture-unknown semantics intact, including the pointer-valued-
  end witness the amendment requires (fit §6: absolute `data`/`data_end`,
  both divergence directions asserted).
- **G2 — semantic gate.** Host twins / worker-oracle cells for the
  surviving core pass with C-cell meanings unchanged (C22 still a
  disclosed divergence, C18/C19 still earlier parse-fail controls, C1
  still geometry-only). No cell is weakened to fit; a semantic failure
  stops the arm (fit §8).
- **G3 — K1 gate (the only number that counts).** Complete object:
  sink + gate + surviving arms at all 11 call sites, mask map, reason
  mirrors. Pass requires ≤850,000, floor PASS,
  `override_consumed: false`, and an identical-source confirmation
  build also passing (fit §8 step 6). A result in 830,000–850,000
  additionally requires the plan's written headroom-recovery follow-up
  (plan §9-K1). Slice or partial-object numbers are not K1 evidence
  and must not be reported as such.
- **G4 — Class-R gate.** Only after G3: C1–C35 `BPF_PROG_TEST_RUN`
  cells (minus the Q1/C23 cells transferred to S7, which must be
  *absent-by-transfer* in #16009's record, not failing) and the
  dual-stack smoke in the Class-R VM lane (`make vm-test-root`), which
  the lane log records as NOT-EXAMINED on the workstation.

### 7.2 Kill criteria for route (b) (any one kills the route)

1. **Scope kill:** the owner will not adopt §6.1 verbatim-or-edited-in-
   the-open, or will not file S7 concurrently. (Route (b) without its
   honesty act is silent narrowing and is prohibited, not merely
   discouraged.)
2. **Core kill:** the surviving core fails G3 (reject, >850,000, or any
   consumed override), after G1/G2 have passed for the arms it
   contains. Consequence is §7.4, not a second scope reduction.
3. **Arm kill:** IPv4 or IPv6 cannot produce a non-access-rejecting
   isolated shape within the bounded attempt discipline. The route
   then cannot claim its §5 core; see §7.4.
4. **Contract kill:** fitting the core is shown to require widening
   `ParsedPacket`/`ExtWalk`, changing `MAX_EXT_HDRS`/walk rules, gating
   transit, moving a LAND call site, or omitting a terminal arm. Those
   are the plan's invariants; breaking one is a new plan, not route (b).
5. **Honesty kill:** any artifact (issue text, test name, log, release
   note) describes #16009 as providing Q1 parity before S7 passes.
   This kills the *landing*, and the text must be corrected before the
   sequence resumes.

### 7.3 Bounded-work discipline carried forward

The verifier-fit §8 budget (bounded isolated attempts per arm, bounded
complete-object compositions, one identical-source confirmation) is
adopted as the ceiling for work under route (b), reduced by the shapes
already measured: shapes recorded as rejected in §3.1 must not be
rerun unchanged. This re-plan spends no verifier budget itself and
authorizes none; it asks the seats to re-authorize a bounded envelope
for the reduced scope, with the stop rule intact.

### 7.4 Escalation if route (b) dies

Exactly the landed plan's escalation, made explicit: return to
architecture step 0 with routes (a) and (d) re-opened on equal footing,
carrying (i) the G1–G3 evidence, (ii) §4.2's contract table as the
starting specification for any redirect design (including the
worker-absent default, which must be decided before any redirect code),
and (iii) §4.3's successor drafting if (d) is chosen. Narrowing again
(second scope removal) is prohibited by plan §9-K1 and by this
document: after (b), the remaining choices are architectural, not
editorial.

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
2. **A measured G1 pass for all three arms *with* Q1 included, plus a
   stack report ≤512 for the TCP chain**, even without a complete
   object. → Weakens (b)'s premise (“Q1 removal is the available
   reduction”); the correct act becomes continuing bounded fitting
   under the original scope rather than adopting §6.
3. **Evidence that Q1 removal saves nothing** — e.g., a complete-object
   diagnostic (not a slice sum) showing the no-Q1 object still rejects
   on the same access/cap signatures. → (b) buys honesty but no
   feasibility; if that is shown *before* adoption, prefer going
   directly to the §7.4 escalation and weighing (a) vs (d), rather than
   spending the one permitted scope reduction for no headroom.
4. **A redirect design that answers §4.2's table in writing** —
   including a worker-absent default that neither re-opens the bypass
   nor drops local/control traffic, per-arm qualification of worker
   flow/flowless verdicts, and a measured complete-object count.
   → (a) becomes competitive and should be re-scored against (b) on
   contract risk, not dismissed categorically.
5. **Evidence the bypass is unreachable or already mitigated** on the
   11 arms (e.g., a proof that terminal-pass traffic is screened
   elsewhere, contradicting §2.1). → (d) becomes correct: close the
   approach, carry the (now hypothetical) requirement in successors.
6. **A kernel/toolchain change** (verifier, bpf-linker, or pinned
   toolchain) that legalizes a measured-dead access shape or raises
   the effective state/stack envelope, demonstrated on the recorded
   failing slices. → Re-run the falsifier in item 1 under the original
   scope before adopting any scope change.

Absence of these items is the current state of the record; the
recommendation in §1 is made on the record as it stands, and §3's
censoring/non-additivity limits (§3.2) apply to any new number brought
against it.

---

## 9. Risks of the recommended route (stated for the seats to attack)

- **Coverage-window risk.** Between #16009 landing under (b) and S7
  landing, the four Q1 predicates are unscreened on host-bound
  kernel-PASS traffic. Mitigation is procedural only: §6.1's wording,
  S7 filed concurrently (not “later”), and §7.2 kill criterion 5.
  A seat that judges the window unacceptable should reject (b) for
  that reason explicitly, rather than approve (b) and hope S7 is fast.
- **False-progress risk.** A passing no-Q1 K1 could be misread as “the
  verifier problem is solved”, pressuring S7 to re-add Q1 by folklore
  tweaks. §6.2's added K1 clause and §7.3's no-rerun discipline are
  the countermeasures; S7 inherits the stop rule, not just the matrix.
- **Scope-creep-by-analogy risk.** §6.3 addresses it: further removals
  require choosing (d) openly. Reviewers should treat any follow-on
  “small additional trim” proposal as a route change requiring this
  same three-seat process.
- **Residual-core risk.** The surviving core contains the two arms
  (IPv4 options, IPv6 observer) with the worst measured signatures.
  Route (b) may therefore still fail at G1/G3, having spent its one
  honest reduction. §7.4 pre-commits the escalation so that outcome is
  a decision point, not a drift into unplanned narrowing.

---

## Appendix A. Source map (so reviewers can check every load-bearing claim)

| Claim in this document | Source |
|---|---|
| Bypass mechanism; 11 arms; two pre-parse CPUMAP exclusions | Landed plan §1 |
| Narrowed core list; C1-is-geometry-only honesty | Landed plan §2 |
| Redirect changes terminal-arm contract; `pass_local_control` intentional (`lib.rs:1812-1816`) | Landed plan §2.1 |
| Anti-split argument (one gate/map/ABI; partial-parity risk) | Landed plan §2.2 |
| Q1 included, four independent bits 5–8, C23 128 outcomes | Landed plan §4.4 |
| Zero-widening invariant; scratch laundering precedent (+298,128 / cap contrast) | Landed plan §5.1–§5.2, verifier-fit §2 |
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
