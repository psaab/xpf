# #16009 — architecture step-0 design after G1 (selective redirect vs geometry-first split vs plan-kill)

- **Status:** design/research only. This document authorizes no code, no
  verifier run, no scope change, and no artifact generation. It compares
  three architecture routes left open by the converged G1 record and
  recommends one for hostile three-seat review. Any scope change,
  successor filing, or campaign spend requires a separate recorded act
  after that review.
- **Governing inputs (all read for this document; nothing re-measured):**
  - Parent final G1 record on issue #16009, `issuecomment-6675710585`
    (2026-11-06; "G1 FINAL (parent) — V6-1 replacement measured: CAP
    REJECT; G1 closed; step 0 next"). This is the sole authority for
    G1's final dispositions, the G2 diagnostic-kill, the non-adoption
    of §6.1, and the remaining budget. Where this document and that
    record disagree, the record governs.
  - Full G1 evidence: `/var/worktrees/campaign-drive/g1-results.md`
    (lane `Impl16009G1`; cited below as `g1-results.md:<lines>`). The
    issue thread's earlier parent synthesis (`issuecomment-6675609580`)
    and the three G1 adjudication seats (`6675500896`,
    `6675582825`, `6675614112`) are cited only where their wording
    constrains a route; the final record supersedes them on disposition.
  - `docs/research/16009-host-screen-plan.md` on master (cited as
    "landed plan"), especially §1 (verified mechanism, 11 arms), §2.1
    (rejected redirect), §2.2 (rejected split), §5.2–§5.5 (shim
    mechanism), §9-K1/K4, and §10 (S1–S6 and conditional S7 titles).
  - `docs/research/16009-verifier-fit-design.md` on master (cited as
    "fit design"), especially §1 (K1), §3 (pre-G1 failure matrix),
    §4–§6 (V6/V4/TCP candidate shapes), §7 (composite ranking), §8
    (bounded prototype protocol, stop rule, 13-run budget).
  - `docs/research/16009-replan-design.md` on master (cited as
    "re-plan"), especially §4.1/§4.2 (route (c)/(a) first fair
    statements), §7.3 (G1 failure taxonomy), §7.4 / §8 (return to
    step 0).
- **Trigger.** G1 is complete and closed. Every rank-1 fact arm has a
  measured disposition and none fits: V6-1 cap-rejected, V4-1
  link-failed, TCP-1 gate-failed on preserved substrate with its stack
  question unadjudicated. The preconditions for every rank-2/rank-3
  fallback are false, the exact rank-1 set cannot compose into a G2
  diagnostic, and §6.1 was not adopted (`6675710585`). The re-plan
  §7.4 sequence therefore reaches this document: compare selective
  redirect (a), geometry-first split (b here; route (c) in the
  re-plan's lettering), and plan-kill (here (c); route (d) in the
  re-plan) with the G1 evidence in hand. Option lettering in this
  document follows the step-0 assignment: (a) selective redirect,
  (b) geometry-first split, (c) plan-kill. The re-plan's route (b) —
  the Q1-removal / §6.1 narrowing — is **not** an option here: it was
  considered, its G2 precondition failed, and the parent record states
  §6.1 is NOT adopted. It re-enters only through §10's flip conditions.

---

## 1. Recommendation (one route)

**Recommend route (b): an IPv4-geometry-only shim gate, with the
existing worker path retained for packets already delivered there and
successors for the rest. This is a partial remediation, not a closure
of #16009.**

1. Retain only IPv4 POD / teardrop geometry, using the existing
   `parse_ipv4` locals. No IPv6 fragment geometry is retained:
   today's `ExtWalk` lacks Fragment offset/M/data length. The worker
   continues screening facts on packets that already reach stage 10;
   this route adds no redirect, so facts on kernel-PASS arms remain
   unresolved until their successors land.
2. Do not add ICMP-fragment, SYN-fragment, Q1, TCP tiny/capture,
   IPv4 option/TLV, Routing type, duplicate-fragment, or other facts
   to this one-family gate. Some existing `ExtWalk` fields can support
   classifications without a new walk output, but that is not a
   measured complete-gate fit; §3.4 gives the exact limit.
3. Keep one outlined gate at all 11 selected terminal arms, the
   checked per-CPU packed-word sink, raw-ingress zone-mask map, and
   aggregate reasons 21/22. Measure this no-new-extraction shape under
   §8 before any implementation or scope act.

**This route does not satisfy the issue's current decisive acceptance**
(overlapping-fragment / LSRR / ICMP-fragment local-address traffic must
drop with a counter): true overlap is S1 state, LSRR is deferred to S8,
ICMP-fragment to S11, and IPv6 fragment geometry to S9. #16009 stays
OPEN until those acceptance requirements are met by successors or the
owner explicitly revises acceptance after review. This is the smallest
bounded candidate for partial remediation, never a fix for the whole
issue.

**Why recommend (b) over (a) selective redirect:** route (a) could
screen source-route and duplicate-header facts at the worker without a
new shim parser, but only on healthy arms with a selected worker path.
For its bounded candidate (§4.2), worker-absent / overload has a
two-way contract conflict: dropping preserves screening but breaks
`pass_local_control`; passing preserves that contract but restores the
bypass. The binding-not-ready arm has no ready worker/binding; the
ctrl-disabled arm is deliberately configured not to use the worker.
Neither redirects. Route (b) has no worker-availability dependency
and keeps the `pass_local_control` path for non-tripped packets; it
intentionally drops configured retained matches before terminal pass,
check. The issue's LSRR/overlap/ICMP-fragment acceptance remains open
either way.

**Why recommend (b) over (c) plan-kill:** the checked sink-only slice
passed at 755,620, and none of the G1 failures measured that sink or
the terminal gate; they localized to carried walk state, TLV parsing,
or the TCP substrate. That does not prove the geometry-only complete
object fits — §8 decides it — but it leaves one falsifiable shim
hypothesis with no new packet read or walk output. Killing the whole
shim approach before measuring that narrower hypothesis would discard
the only measured-alive transport. If §8 rejects this no-new-extraction
shape, route (b) is killed and plan-kill is reconsidered (§9).

The specific subset is deliberately narrower than "all geometry":
existing `ExtWalk` booleans support IPv6 fragment classification, but
not IPv6 fragment offset / M / data length. No extension-walk fact
newly carried out of the walk is assumed cheap (§3.4).

## 2. G1 ground truth (measured; the only numbers this document uses)

### 2.1 Definitions

- **"fits"** (fit design §1, §8): an isolated shape passes its
  semantic/access/stack gates **and** a complete object containing it
  measures **≤850,000 processed insns of the 1,000,000 cap, floor PASS
  (≥15% headroom), `override_consumed: false`** — confirmed by a
  second identical-source build. Only a complete-object measurement
  is K1 evidence; an isolated or partial count is a diagnostic, never
  a fit. `XPF_SHIM_ALLOW_LOW_HEADROOM` MUST NOT waive any result.
- **K1** is unchanged from the landed plan §9 and fit design §1. The
  baseline object measured **779,213 / 1,000,000** (22.0787% headroom)
  in `pkg/dataplane/userspace_xdp_gate_verdict.json` at `6c27f54cf2`;
  slack to the 850,000 ceiling is 850,000 − 779,213 = **70,787 insns**.
- **Budget:** fit design §8 authorized **13 verifier runs** (9 isolated
  shapes + 3 complete-object compositions + 1 identical-source
  confirmation; 14 only for a changed-input baseline). **4 are
  consumed, 9 remain**, held for the step-0 design's own bounded
  protocol (`6675710585`). No run in this document is authorized by
  this document.

### 2.2 Final per-arm dispositions

| Arm (rank-1 shape) | Final disposition | Evidence |
|---|---|---|
| **Baseline** (pristine master object) | PASS, 779,213; reused, not rerun (build-input diff empty) | `g1-results.md:18-29` |
| **Sink-only slice** (checked per-CPU scratch write/read, no fact arm) | PASS, 755,620 — *23,593 below baseline* | pre-G1 matrix, fit §3; re-plan §3.1 |
| **V6-1** — stack-only accumulator in the existing walk, map I/O after return | **MEASURED FAILURE — instruction cap.** Corrected replacement run (4 of 13): REJECT, `BPF program is too large. Processed 1000001 insn`; 28 max states/insn, 38,707 total states, peak 2,011; `override_consumed: false`. Stack line sums to 640 B over 19 frames (max frame 320 B) — recorded as evidence, *not* a separate stack rejection (run ended on cap). | `g1-results.md:98-155`; parent final `6675710585` |
| **V4-1** — fixed-offset selector, bounded unrolled TLV machine over held IHL slice | **MEASURED FAILURE — link.** `bpf-linker` / LLVM: "Looks like the BPF stack limit is exceeded… in function `try_xdp_userspace`"; 56 identical `ERROR llvm:` lines. No object generated; no insn/stack numbers exist for this run (link precedes verification). | `g1-results.md:157-198`; `6675710585` |
| **TCP-1** — shortest fact lifetime (placement only; write packed word before address materialization) | **GATE FAILURE — packet access in preserved substrate; TCP mechanism and stack NOT adjudicated.** REJECT `invalid access to packet, off=56 size=1` (the preserved IPv6 dynamic Routing-header read, not the TCP-1 shape); verification aborted at 30,275 processed insns (early-exit diagnostic, not a count). Emitted stack chain sums to 632 B over 19 frames (max frame 312 B) but **no stack verdict was emitted**. | `g1-results.md:200-257`; seat wording correction `6675614112`, accepted in `6675710585` |
| V6-1 initial attempt | Not a measurement: Rust compile stop (arm edit transiently dropped pre-existing `eh_class` imports; restored post-run; shape never presented to the verifier). Superseded by the seat-authorized replacement above. | `g1-results.md:67-96` |
| V6-2R / V6-3 / V4-2 / V4-3 / TCP-2 / TCP-3 | **Not run; preconditions all false** (§2.3). | `6675710585` |
| G2 no-Q1 complete-object diagnostic | **Diagnostic-killed without spending a composition slot:** the exact rank-1 set contains link-unbuildable V4-1, so a composition fails at link with zero verifier information. §6.1 NOT adopted; no S7 filing. | `6675582825` (GLM), parent ruling `6675609580`, final `6675710585` |
| §6.1 Q1-removal scope change | **NOT adopted.** Q1 remains in #16009's scope on the record; it has not been transferred, and no artifact may claim otherwise. | `6675710585` |
| Class-R BPF cells / dual-stack smoke | **NOT-EXAMINED.** Owed by any future route's validation lane (`make vm-test-root`); no route below may cite them as evidence. | re-plan §7.1 G4; `6672054613` |

### 2.3 Why every fallback precondition is false

Fit design §8 routes to a rank-2/3 shape only by the measured failure
signature of the rank-1 shape. G1's signatures close every door:

- **V6-2R** (widened v6-fragment laundering slot) requires the V6-1
  rejection to localize to post-walk map/gate state. V6-1 instead
  failed walk-locally at the instruction cap with the accumulator
  inside the existing walk and map I/O already deferred until after
  the walk returned (`g1-results.md:39-49`). V6-2R keeps that walk and
  accumulator unchanged (fit §4), so it cannot cure the failure it
  would inherit. Precondition false (`6675710585`).
- **V6-3** (second pass through the same walker) requires the
  rejection to localize to observer-state coupling that a split pass
  addresses. A second pass executes the same walk a second time; it
  does not reduce the per-walk verifier state that capped V6-1, and
  it retains the same checked routing-type read (fit §4: "it is not
  an access fix"). G1 attributes the cap to walk-state explosion
  (`6675710585`: "the verifier state explosion the fit doc flagged as
  its uncertainty" — fit §4 V6-1 uncertainty paragraph). Precondition
  false.
- **V4-2** (held-slice stack copy) is admissible only if V4-1 fails on
  packet-access tracking (fit §8 step 3). V4-1 failed at **link**, a
  layer §8's IPv4 routing does not map to V4-2; and the stack-copy
  family is already measured dead pre-G1 (`off=35`, fit §3).
  Precondition false.
- **V4-3** (split malformed/route passes) is admissible only if
  fixed-offset access is *accepted* but the one-pass state shape is
  rejected (fit §5, §8). V4-1's fixed-offset access was never accepted
  or rejected by the kernel verifier — the object never linked.
  Precondition false.
- **TCP-2** (Q1 trips derived in the outlined gate) requires a TCP-1
  stack adjudication — a per-frame or combined-chain value >512 B
  (fit §6, §8 step 4). TCP-1 produced no stack verdict; the 632 B
  chain sum is emitted evidence from an aborted verification, not an
  adjudication, and the seats explicitly forbade auto-selecting TCP-2
  from it (`6675500896`). Precondition false.
- **TCP-3** (outlined scalar helper) requires TCP-2's gate placement
  to have failed its own budget. TCP-2 was never run. Precondition
  false.

**Consequence:** there is no lawful next verifier run inside the fit
design's protocol. Any future run belongs to a new bounded protocol
(§8) under a route chosen at this step 0.

### 2.4 Procedural facts that constrain this design

1. **Order deviation, accepted.** G1 executed TCP-1 → V6-1 → V4-1
   (parallel dispatch), not fit §9's V6-1 → V4-1 → TCP-1. All three
   seats accepted this as non-invalidating (intra-arm selection is
   the order's decision content; no arm reached variant selection),
   and recorded it as a protocol deviation, not conformance
   (`g1-results.md:4`, `6675710585`). §8's protocol therefore mandates
   strictly sequential execution.
2. **First-abort-layer evidence only (GLM residual, carried as a
   design constraint).** Every G1 arm embedded the other arms' facts
   at known-good placement in the shared substrate
   (`g1-results.md:11`), so each run reports only the first layer
   that aborted: TCP-1's result says nothing about its own stack, and
   a different substrate failure could have masked a V4-1 verifier
   result had it linked. The parent record carries this forward
   verbatim: "any future isolated measurement must not embed
   known-failing substrate, or its results stay first-abort-layer
   only" (`6675710585`). §8 makes this a hard construction rule.
3. **Run-cap exception, recorded.** The fourth (replacement) run
   exceeded G1's original 3-run dispatch cap by one, under explicit
   three-seat concurrence as a one-time compile-fault exception,
   charged 4/13 with no further replacement on any outcome
   (`g1-results.md:296-314`; `6675614112`). The 13-run ceiling binds
   the orchestrator as well as the lane; §8 inherits that reading.
4. **Nothing landed.** All G1 changes remain in scratch worktrees; no
   object was installed (`pkg/dataplane/userspace_xdp_bpfel.o` still
   hashes to the baseline `51e4b644…` in every arm;
   `g1-results.md:273-295`); no commits were made. The dirty
   `wt-16009impl` tree is preserved as the pre-G1 experiment record.
   #16009 stays OPEN; the security defect is unclosed
   (`6675710585`).

---

## 3. Verifier-feasibility arithmetic (grounded in G1, not folklore)

This section uses only §2's measured numbers and arithmetic on them.
Where a quantity was never measured, it says so and draws no number.

### 3.1 The headroom equation every route must satisfy

```
cap                 = 1,000,000 processed insns
landing ceiling K1  =   850,000   (floor: ≥15% headroom, override false)
baseline (measured) =   779,213   → slack to ceiling = 70,787
sink-only (measured)=   755,620   → slack to ceiling = 94,380
```

Three facts in this table do real work:

1. **The sink is not the blocker, and slice costs are not additive.**
   Adding the checked per-CPU scratch mechanism *lowered* the measured
   total by 23,593 insns versus baseline (fit §3 F1 conclusion;
   re-plan §3.2). Any argument of the form "baseline + arm A + arm B"
   is thereby disproved as a prediction method for this object. No
   route below is priced by summing deltas; each is priced only by
   what fraction of its shape has already been measured to pass.
2. **Every 1,000,001 figure is censored.** V6-1 stopped *at* the cap;
   its complete count is unknown and is at least 150,001 insns above
   the landing ceiling. The pre-G1 matrix shows the same signature
   for three further IPv6 forms (fixed-prefix 63,606 states;
   map-accumulating 61,589; out-of-line 61,135 — fit §3). Four
   distinct accumulator placements share one signature: the cost is
   in maintaining walk-derived state across the walk's downstream
   arms, not in any single placement. That is a *signature*
   conclusion, not a cost estimate — but it is strong enough to kill
   shapes whose only change is where the walk's output is stored
   (V6-2R, V6-3), per §2.3.
3. **Early-exit counts price nothing.** TCP-1's 30,275 and the pre-G1
   `off=34/35/56` counts (99,774–101,488) are the processed-insn values
   at which the verifier refused one access and stopped. They cannot
   be read as "this arm costs ~100k" or "70k of headroom remains."
   The fixed-prefix IPv6 variant proves the point: clearing the
   access reject moved the result to the 1,000,001 cap (fit §3).

### 3.2 The stack equation, stated precisely

Kernel BPF stack limit: **512 B per call chain** (and, per fit §8,
each per-function frame and the combined chain are adjudicated
separately; one does not stand in for the other).

| Measurement | Per-frame max | Combined chain | Verdict |
|---|---:|---:|---|
| Pre-G1 IPv4 tiny + post-L4 TCP-trip slice | not reported | **528 B** across 3 calls | REJECT — 16 B over (fit §3; 775,418 insns) |
| G1 TCP-1 run | 312 B | **632 B** over 19 frames (prefixes cross 512 at frame 14: 528) | **No verdict** — verification aborted at `off=56` before any stack adjudication (`g1-results.md:244-254`) |
| G1 V6-1 replacement run | 320 B | **640 B** over 19 frames | **No stack verdict** — run ended on the instruction cap; the line is evidence only (`g1-results.md:149-155`) |
| G1 V4-1 run | not emitted | not emitted | Link failure precedes verification; no numeric stack report exists (`g1-results.md:190-192`) |

Honest reading, binding on every route below:

- The **only adjudicated stack failure** in the entire record is the
  pre-G1 528 B combined chain (16 B over). It localizes to the
  IPv4-tiny + post-L4-trip slice as a whole; the lane log does not
  identify the frame, and "only 16 bytes over" is not an inference
  license (re-plan §3.3).
- The G1 632 B and 640 B chain sums **must not** be cited as stack
  failures of TCP-1 or V6-1. Both runs died earlier (access, cap).
  Their chain sums do establish one weaker fact: in the full-object
  context, the emitted call chains already exceed 512 B in aggregate
  before any new gate is added — so any route that *adds* frames to
  these chains starts from an emitted sum with zero slack, and must
  produce an actual per-frame + combined adjudication, not a chain
  sum scraped from an aborted run.
- V4-1's link diagnostic ("BPF stack limit is exceeded… move large on
  stack variables into BPF per-cpu array map") is an LLVM-stage
  rejection of the 40-arm constant-offset dispatch inlined into
  `try_xdp_userspace`. It establishes that the *selector's code
  shape* is link-infeasible in that placement; it establishes nothing
  about a differently-placed or differently-encoded options scan,
  and nothing numeric.

### 3.3 What is actually verifier-cheap, per fact family

"Cheap" below means: the fact's inputs already exist as validated
scalars at a point the parser reaches today, so the shape adds no new
packet read, no new walk output, and no new live range across
`ParsedPacket` construction. This is a *construction* claim checkable
against the landed plan §5.3 and `ExtWalk` definition, not a measured
fit — only baseline and sink-only passed in the available record.

**Existing-input candidates (construction claims only; no fact gate is
measured beyond the sink):**
- The route-(b) candidate selects only IPv4 geometry:
  `frag_field`, `total_len`, and IHL-derived data length are already
  bound in `parse_ipv4` (`lib.rs:2292-2355`). POD
  (`offset + extent > 65535`) and teardrop
  (`data_len == 0 || (more && data_len % 8 != 0)`) use these locals.
- IPv4 ICMP-fragment and known-flags SYN-frag can use existing wire
  protocol, fragment classification, and parsed flags. They are not
  geometry and are excluded from the single-family route-(b) shape;
  their complete-gate costs are unmeasured.
- IPv6 ICMP-fragment and known-flags SYN-frag can reuse today's
  `ExtWalk.fragment_seen`, `non_first_fragment`, terminal
  `protocol` / `offset`, and existing parsed flags. This reuses
  existing outputs, not a new walk fact; no complete gate using them
  is measured, so route (b) defers them.

**Not in the cheap subset:**
- IPv6 POD / teardrop geometry needs the Fragment header's offset,
  M bit, and fragment data length. Those values are read inside the
  existing walk, but are **not** fields of today's `ExtWalk` return
  (`ipv6_ext_walk.rs:191-226`). Carrying them out is a new
  walk-derived output — exactly the state-multiplication risk V6-1
  measured. Re-reading the header after the walk would be a new
  packet-access shape, unmeasured, and not assumed cheap here.
- Routing type (`rh[2]`) and duplicate non-atomic count require
  additional walk output. V6-1 cap-rejected this class of accumulation.
- IPv4 options facts (LSRR/SSRR sighting, malformed verdict): all
  tested access shapes failed — dynamic scan (`off=34`), static-
  dispatch checked-byte reader (pointer-from-scalar), stack copies
  (`off=35`), fixed-offset selector (link, V4-1).
- TCP tiny/capture-unknown + trips: the pre-G1 528 B stack failure
  is adjudicated for the combined tiny + post-L4 slice; TCP-1's own
  placement variant remains unadjudicated because its substrate
  aborted first.

### 3.4 Is ANY extension-walk fact cheap? (direct answer)

**No *new* extension-walk fact is measured cheap.** The existing
`ExtWalk` outputs (`offset`, terminal `protocol`, `non_first_fragment`,
`fragment_seen`, `exhausted`) are already computed and consumed by the
baseline parser; reusing those exact outputs at their existing
convergence point adds no new walk state. That does not make every
semantic consequence cheap: the first-fragment word, M bit, and data
length are absent from `ExtWalk`, as are Routing type and duplicate
count. V6-1's deliberately minimal accumulator (validated routing
prefix scalar across one revalidation, duplicate notification, no map
I/O in the walk, map write after return) hit 1,000,001 with 38,707
states; the earlier fixed-prefix diagnostic reached 63,606 states
(`g1-results.md:120-155`; fit §3). The emitted evidence forbids
assuming that adding any one such value is cheap, but does not prove
that a distinct post-walk reread can never work.

The scratch-laundering precedent for preventing state multiplication
cost **+298,128 insns** in its measured instance (landed plan §5.1),
which is 298,128 / 70,787 = **4.21×** the entire baseline slack to
the K1 ceiling. [INFERENCE] Any proposal to launder new walk facts
therefore begins with a measured precedent larger than the available
slack; it must show a different measured cost, not cite the precedent
as free. The only currently reusable IPv6 facts are the exact
`ExtWalk` fields already returned — e.g. `fragment_seen` can
participate in ICMP-fragment and first-fragment classification. No
new Routing type, duplicate count, or fragment-geometry word is
within the geometry-first subset. Otherwise redirect (§4) to a
qualified worker path or keep the fact in a successor.

### 3.5 Feasibility ledger (what each route may claim today)

| Claim | Baseline | Sink | No-new-extraction gate | New walk facts at shim | TLV facts at shim | TCP tiny/Q1 facts at shim | Redirect classifier + XSK redirect |
|---|---|---|---|---|---|---|---|
| Measured PASS exists | ✅ 779,213 | ✅ 755,620 | ❌ unmeasured | ❌ V6-1 cap; earlier cap variants | ❌ 3 access + 1 link | ❌ 528 B pre-G1 slice; rank-1 unadjudicated | ❌ unmeasured for these arms |
| Needs new packet read | — | no | no | carry or reread (unmeasured) | yes (all measured forms failed) | no new read; stack shape failed | classifier uses existing fields; unmeasured |
| Needs new walk output | — | no | no (reuses existing outputs only) | yes (V6-1 cap signature) | no | no | no (worker parses) |
| Availability price | none | none | none | none | none | none | **yes — §4.3** |
| Decidable by | — | done | §8 protocol (2 runs) | successor protocol, clean-room | successor protocol, clean-room | successor protocol, clean-room | §4.5 acceptance + complete-object run |

---

## 4. Route (a) — selective redirect-to-worker for a bounded host-bound superset

### 4.1 Shape

At selected terminal arms, redirect a packet to the existing AF_XDP
worker only when a cheap classifier recognizes that the packet may
contain a fact the geometry gate cannot extract. The classifier uses
already-available packet metadata; it does not attempt to decide
whether a screen actually trips. The existing XSK redirect tail is
`USERSPACE_XSK_MAP.redirect(binding_slot_ready, 0)` at
`userspace-xdp/src/lib.rs:1269`; after redirection, the worker's stage
10 (`stage_screen_check_with_ambiguous`, `poll_stages.rs:1100ff`)
runs its own verdict path.

### 4.2 Arms and exact bounded superset

The candidate deliberately chooses only two healthy local-delivery
arms whose dispatch point has a ready worker slot and whose packet
is intended for local handling. It does not claim parity on all 11
terminal arms.

| Arm | Redirect? | Superset | Boundary |
|---|---|---|---|
| Session-hit `PASS_TO_KERNEL` | **Candidate: yes** | Parsed IPv4 where `l4_offset > l3_offset + 20` (IPv4 options present), or parsed IPv6 where `l4_offset > l3_offset + 40` (one or more extension headers) | Must prove the worker re-handles a session-hit packet without changing its established kernel-pass semantics; otherwise remove this arm and leave its facts unclosed. |
| Session-miss local destination | **Candidate: yes** | Same predicate | This is the clearest exact-local worker path; qualification still required for zone, flowless screen order, and local delivery. |
| WG steer | **No** | — | Kernel WireGuard termination remains a control/data-plane steer, not a generic worker round trip; inner screening stays S5. |
| Early-filter multicast / limited-broadcast | **No** | — | Worker does not screen these classes; redirect would invent a policy path. Geometry behavior here remains the landed plan's explicit extension. |
| Session-miss NAT-external NDP / proxy-NDP | **No** | — | Preserve kernel NDP liveness; no worker path demonstrated for these control-plane actions. |
| Session-miss ICMP-to-interface-NAT local | **No** | — | Keep the selected ICMP local path; no redirect contract demonstrated. |
| Interface-NAT tunnel kernel pass | **No** | — | Preserve tunnel termination ownership pending a worker-path proof. |
| GRE-inner `PASS_TO_KERNEL` | **No** | — | Redirecting the outer packet changes decapsulation ownership; inner parity remains S5. |
| Binding-not-ready degraded local/control | **No** | — | No ready slot exists; this arm is specifically `pass_local_control`. |
| Ctrl-disabled local/control | **No** | — | The operator chose no worker adjudication; this arm is specifically `PassLocalControl`. |

The superset catches IPv4 options without decoding their TLVs and IPv6
extension chains without producing a new `ExtWalk` output. Thus IPv6
ICMP-fragments with extension headers may reach the worker, but plain
IPv4 ICMP-fragments without options do not; the worker's ICMP verdict
and parity still require proof, so route (a) claims no complete ICMP
leg. It also routes benign options / extension packets (false positives)
and does **not** catch TCP-only Q1/tiny facts on packets with no options
or extensions, classify true fragment overlap, or change the worker's
LocalDelivery overlap recording gap (S1). The other nine arms and these
uncovered classes remain explicit residues. This is not a complete
repair of #16009.

The membership proof must establish, for these two arms, that every
IPv4 option packet and every IPv6 extension-chain packet whose worker
verdict can differ is in the superset. Since this classifier selects
all options / extension chains rather than actual trips, no dynamic
TLV parse, Routing-type read, or duplicate counter is added to the
shim. The classifier itself still requires a full-object measurement;
no instruction-cost estimate is claimed.

### 4.3 Worker-absent / overload default

For a packet that reaches a selected redirect arm while the worker
is unavailable or overloaded, the two possible defaults conflict:

- **Fail closed:** drop the superset packet; never fall back to
  `XDP_PASS` / `cpumap_or_pass`. This preserves the screen guarantee
  on that arm but breaks the `pass_local_control` availability
  contract for the affected local/control packet.
- **Fail open:** use `pass_local_control` / kernel pass. This
  preserves availability but re-opens the bypass for that packet.

There is no default that simultaneously screens the packet and
preserves `pass_local_control` when the worker cannot run. Overload
must be treated the same way: a redirect error/full-queue condition
must not silently fall back to kernel pass. The route must specify
which condition the shim can actually observe, how it is detected,
and prove that any unobservable XSK delivery failure cannot be
misreported as a screened worker verdict. No such proof or health
contract is in the current evidence.

### 4.4 `pass_local_control` contract

Route (a)'s redirect call-sites are below the binding-ready success
point (`lib.rs:896`) and appear only in the two §4.2 arms. The
binding-not-ready arm (`lib.rs:891-894`) and ctrl-disabled arm
(`lib.rs:1726-1728`) contain no redirect, so they continue to invoke
`pass_local_control` unchanged (`lib.rs:1812-1816`). This preserves
those excluded arms' existing path, not an end-to-end guarantee:
fail-closed on a selected arm after worker loss breaks availability,
and options/extension-bearing packets in excluded arms still pass as
today. Closing those bypasses needs a changed `pass_local_control`
policy or independent enforcement, a new owner decision.

A redirected worker verdict is not a shim `host_screen_drop`, and the
landed plan's aggregate reason/counter acceptance cannot be claimed
for it. The worker's own screen counters/events may observe it only if
the qualified worker path does so; this remains a proof obligation.


### 4.5 Acceptance required before recommending (a)

1. A parser-state proof that the IPv4 `l4_offset > l3_offset + 20`
   and IPv6 `l4_offset > l3_offset + 40` classifier covers every
   source-route, malformed-options, Routing-type, and duplicate-
   Fragment packet on both selected arms; host sampling is not proof.
2. An end-to-end worker-path test for each arm proving the correct
   flow/flowless entry, zone, exact-local disposition, and unchanged
   session-hit behavior. The flowless screen deliberately omits TCP
   flag checks (`screen/mod.rs:1262-1276`), which is another reason
   this candidate does not claim Q1.
3. An explicit worker-absent / overload policy. If fail-closed,
   owner approval of the `pass_local_control` availability change;
   if fail-open, acceptance of the residual bypass. Test worker
   absence at bind time, death after ready, full queue, and HA
   restart, and assert no false worker-screen accounting.
4. Zone/raw-vs-claimed semantics per arm; any difference is assigned
   to S6.
5. A complete generated-object measurement of this exact classifier
   and redirect placement under §8's clean-room rules.
6. A source census confirming only the two named arms redirect and
   the degraded / ctrl-disabled paths do not.

### 4.6 Verdict on (a)

**A bounded, unmeasured partial route — not the full worker redirect
and not a default-safe closure.** It moves some extension/options
facts to the worker without new shim extraction, but only on two
arms, only with a qualified worker path, and only while its
availability default is accepted. Preserving `pass_local_control`
necessarily leaves a worker-absent bypass in the excluded degraded
arms; changing that contract has a substantial availability cost.
It remains the escalation route if (b) fails and an owner accepts
that contract, but no measured evidence prices its verifier or worker
semantics.

---

## 5. Route (b) — geometry-first split (geometry-only shim gate + worker for the rest)

### 5.1 Shape of the route

#16009's shim gate evaluates only IPv4 POD / teardrop geometry using
existing `parse_ipv4` locals. It emits no ICMP-fragment, SYN-fragment,
TCP, IPv4-option, or IPv6 fact. Worker stage 10 continues screening
other packets that already reach it; this route adds no redirect, so
facts on kernel-PASS arms stay open for successor work. No new
extension-walk output is proposed: even the existing `ExtWalk` bits
support only classifications, not IPv6 POD / teardrop geometry. The
cut is one geometry family, not the landed plan's Q1-only §6.1 cut,
which would have retained unfit V4/V6 fact arms.

### 5.2 Retained vs deferred (exact boundary)

**Proposed retained set (only if route (b) is adopted):** IPv4
geometry only, using locals already bound by `parse_ipv4`.

| Retained predicate | Inputs | Evidence of availability |
|---|---|---|
| Ping-of-death geometry (`offset + extent > 65535`) | IPv4 `frag_field`, `total_len` | Existing `parse_ipv4` locals (`lib.rs:2292-2355`) |
| Teardrop geometry only (`data_len == 0 \|\| (more && data_len % 8 != 0)`) | IPv4 fragment word and IHL-derived data length | Existing `parse_ipv4` locals; never claims overlap |
| Candidate integration | Checked packed-word sink plus outlined gate at all 11 terminal arms, raw-ingress `u16` map, aggregate reasons 21/22 | Full integration unmeasured; sink-only scratch slice PASS at 755,620 proves only the checked per-CPU scratch mechanism, not this gate/map/counter shape |

**Deferred to successors** (no exception without new evidence and a
new scope act):

| Deferred fact | Why it is outside this geometry-only boundary |
|---|---|
| IPv6 POD / teardrop geometry (Fragment offset, M, data length) | Those values are absent from today's `ExtWalk`; carrying or rereading them is a new walk output / packet-access shape (§3.3–3.4); S9 owns this fact. |
| ICMP-fragment checks (both families) | Existing inputs do not make a complete gate measured; S11 must own the check or prove a worker/nft path. |
| Known-flags SYN-fragment checks (both families) | Existing parser inputs, but not geometry; S7 owns only after an explicit scope act and a separately measured shape. |
| IPv6 Routing type 0/1 and duplicate non-atomic-Fragment error | New walk-carried facts; V6-1 cap-rejected; S9. |
| IPv4 LSRR/SSRR and malformed-options error | V4-1 link failure plus pre-G1 access failures; no legal form measured; S8. |
| Tiny-declared / capture-unknown and flags-unknown SYN-frag error (either family) | TCP-1 aborted in substrate; pre-G1 tiny + post-L4 slice failed stack at 528 B; S10. |
| Q1 TCP-flag family | §6.1 was NOT adopted; Q1 remains in #16009 unless a new scope act assigns it to S7. |
| True overlap, scan/sweep, SYN-cookie, zone/reason event fidelity, GRE-inner, claimed-zone | Already assigned to S1–S6 by landed plan §10; unchanged here. |

**Boundary rule:** only existing IPv4 `parse_ipv4` geometry locals feed
this gate. No `ExtWalk`, post-L4 flag, IPv6 geometry, new packet read,
new walk output, TLV scan, retained scalar across walk revalidation, or
new live packet slice/range is permitted in this route. The packed word
in §5.3 is the sole planned carry channel. Any additional predicate
requires its own measured shape and explicit scope act.

### 5.3 What the split changes in the landed plan's artifacts

- **Packed word:** emit only IPv4 POD and teardrop decision bits.
  No IPv6 geometry, ICMP-fragment, SYN-fragment, source-route, Q1,
  malformed, duplicate, or tiny/capture facts are carried.
- **Zone-mask `u16`:** only the retained POD/teardrop bits plus the
  existing alarm-without-drop bit are meaningful. The Go builder and
  `ScreenProfile::conservative_default` rows zero every deferred bit.
  [INFERENCE] This narrows the landed plan's §6.2 builder deltas but
  does not change their shape; `AlarmWithoutDrop` for inert and
  `BadNumericUnresolved` references (fold F-C) applies to retained
  bits. Extractor-error row-presence drops for C20/C21 are not
  retained predicates and transfer with those facts.
- **Cells:** the scope-act artifact must give an exact C1–C35
  disposition. C1/C4 IPv4 geometry are candidates for retained
  coverage; C3 ICMP-fragment, C5 SYN-fragment, Q1 legs, IPv4 option
  errors, IPv6 geometry/Routing/duplicate facts, and tiny/capture cases
  are deferred. C18/C19 remain honest earlier-`PARSE_FAIL` controls,
  not parity. Do not claim all current C24–C34 triggers remain: the
  scope act must identify which arm/control cases still exercise the
  retained geometry gate and transfer the rest using re-plan §7.2's
  cell-by-cell method.
- **Counters:** reasons 21/22 (`host_screen_drop` /
  `host_screen_alarm`) cover only retained geometry dispositions.
  Deferred-predicate drops, when a successor lands them, use the
  worker's existing counters (worker-side) or new append-only reasons
  (shim-side); 21/22 are not reused retroactively.

### 5.4 Why this subset can be believed cheap — and what would prove otherwise

The arithmetic is bounded, not predictive. If the candidate preserves
the 779,213-fit baseline, only 70,787 fits remain to K1's 850,000
ceiling; the sink's separate 755,620 result is not a substitute base
for that calculation (§3.2). The candidate uses only IPv4 locals
already bound by `parse_ipv4`; sink-only proves the checked per-CPU
scratch transport can fit, not the gate at all 11 arms, raw-ingress
zone-mask map, or reasons 21/22 integration. The complete-object cost
remains unmeasured; no additive instruction estimate is claimed. §8's
two-run pair is a diagnostic test of that complete shape, with any
cap/access/link/stack failure killing route (b), not permission to add
or remove another predicate.

### 5.5 Verdict on (b)

**Recommended as the next bounded measurement, not as an accepted
fix.** It reuses measured-alive transport and existing IPv4 geometry
inputs, avoids route (a)'s worker-availability trade, and holds the
gate to one fact family. It keeps `pass_local_control` for non-trips
but intentionally drops configured POD/teardrop matches before
terminal pass; unaffected control-path packets remain Class-R
acceptance. It does not cover the original decisive overlapping-
fragment / LSRR / ICMP-fragment regression: all three legs remain
open. It can be implemented only as an explicitly recorded partial
remediation (original acceptance still open) or after the owner
explicitly revises acceptance, and only if the geometry object passes
§8.


---

## 6. Route (c) — plan-kill the shim approach, with successors carrying the requirement

### 6.1 What plan-kill would assert

That "replicate worker stateless predicates at terminal kernel-PASS
arms" is the wrong mechanism for #16009 as a whole — not merely that
its rank-1 shapes failed. Every requirement must either transfer to a
named successor or be explicitly withdrawn by the issue owner as
accepted risk. Under campaign usage, PLAN-KILL requires all three
seats converging on reject (landed plan §2.2) and must state which
obligation goes to which successor, who owns it, and which tests
establish disposition—or which acceptance is withdrawn (re-plan §4.3).
It does not close #16009 and must never be recorded as a fix.

### 6.2 The successor set plan-kill would need (worker-side vs nftables-side)

Plan-kill transfers each original security obligation; it does not
permit an unowned residual. The successors below are **proposed issue
sketches**, not filed work. Owners must assign every required fact and
arm to a tested path or obtain the owner's explicit acceptance
withdrawal. G1 does not establish either enforcement direction.

- **Worker-side enforcement (redirect-based), proposed PK-W:**
  `worker: screen host-bound kernel-PASS traffic after shim plan-kill`
  — owners: userspace-xdp dataplane and userspace-dp AF_XDP maintainers.
  PK-W must qualify the exact redirect arms/superset, worker verdict
  path, `pass_local_control` default, availability policy, and
  worker-path tests (§4.2–§4.5). The present bounded candidate covers
  only two healthy arms; degraded/control-disabled arms and
  non-superset facts remain unresolved. PK-W cannot carry the full
  requirement until it proves delivery for the original local-address
  regression and assigns every uncovered case to another successor or
  a formally withdrawn acceptance.
- **nftables-side enforcement, proposed PK-N:**
  `nftables: enforce malformed host-bound kernel-PASS screens after shim plan-kill`
  — owner: nftables maintainers. Existing
  `pkg/nftables/host_inbound_screens.go` establishes per-zone flood
  rate meters, not malformed-packet screening. The successor must
  specify concrete expressions, hook placement, fragment visibility,
  per-zone policy, counters, and packet tests for every assigned fact.
  This record has no evidence that nftables can or cannot express
  those predicates. In particular, the lo0/input-hook proposal must
  account for the existing IPv4 prerouting fragment-visibility
  constraint (`pkg/nftables/netlink_lo0.go:30-34`). Facts not proven
  by PK-N remain assigned to PK-W or another named successor; they are
  not silently dropped. [INFERENCE] Splitting enforcement between
  nftables and the worker/shim may add separate counter and event
  semantics, an integration cost S4 must measure.
- **No-enforcement / accept-risk, proposed PK-R:** `#16009: record
  explicit acceptance of host-bound screening bypass` — owner: issue
  owner. It would state that host-bound kernel-PASS traffic remains
  screened only by existing dataplane/nft flood controls and explicitly
  withdraw every unassigned acceptance obligation, including the
  decisive overlapping-fragment / LSRR / ICMP-fragment local-address
  check. Any S1–S6 requirement not withdrawn remains owned by its
  successor. This is not a fix; absent the recorded withdrawal,
  residual requirements remain open.

Before plan-kill adoption, ensure the landed-plan S1–S6 obligations
have recorded owners/issues or explicit dispositions; file PK-W/PK-N
and any PK-R risk record; and rewrite S7–S11's shim-specific ownership
as worker/nft successor assignments (or retain shim successors only
by explicit seat choice). No route inherits a blanket claim that the
worker or nftables already provides enforcement on all 11 arms.

### 6.3 Verdict on (c)

**Not recommended on current evidence.** G1 shows that extraction
shapes are difficult, but the measured sink passed and the
no-new-extraction full gate has not been tried. If §8 kills that
specific gate shape, route (b) is dead; that alone does not prove every
architecture impossible. Seats should compare route (a) with plan-kill
under the new evidence. Plan-kill is justified only by three-seat
convergence that the shim mechanism is wrong for the requirement,
plus named successors for every still-required case (§6.2); the
design does not auto-select it on budget exhaustion.

---

## 7. Comparison, scope act, and successor filing

### 7.1 Comparison matrix (feasibility grounded in §3, not asserted)

| Criterion | (a) Selective redirect | (b) Geometry-first split | (c) Plan-kill + successors |
|---|---|---|---|
| Original decisive regression | Partial only on two healthy arms; overlap, plain IPv4 ICMP-fragments, and excluded arms remain | None of overlap / LSRR / ICMP-fragment is covered; all three stay open | Only successors can close it; accept-risk requires explicit owner withdrawal |
| Fact coverage | Options/extensions routed on two arms; TCP-only Q1/tiny, plain IPv4 ICMP-fragments, and excluded arms remain | IPv4 POD/teardrop only; worker screening applies only where packets already reach it | Worker/nft coverage is unproven and must be assigned fact by fact |
| Measured basis | No classifier/full-object or worker-path measurement for these arms | Sink PASS 755,620 and existing baseline inputs; full 11-arm gate unmeasured | No evidence for replacement enforcement |
| Verifier budget arithmetic | Classifier cost unknown; do not infer "small" | Baseline slack to K1 is 70,787; sink is not an additive budget; two-run diagnostic only | No shim run; successors need their own authorized protocols |
| Availability / `pass_local_control` | Fail-closed affects selected fact-bearing local traffic; fail-open restores bypass; degraded/control-disabled arms excluded | No worker dependency; non-trip packets retain `pass_local_control`, configured matches intentionally drop | Depends on successor; accept-risk leaves bypass by explicit decision |
| Status if adopted | Partial, with uncovered arms and facts explicit | Partial only if owner adopts narrower scope; #16009 stays open for successor requirements | Plan-kill is not a fix; requirements stay open or are explicitly withdrawn |
| Fastest next evidence | Worker-path, health-contract, and complete-object qualification | D1/D2 candidate diagnostic (max two runs) | Requires new successor designs and protocols |

### 7.2 Sequence required for route (b)

1. Three-seat review records whether this design is PLAN-READY and
   authorizes only the exact D1/D2 diagnostic pair in §8 (at most two
   of the nine remaining runs). The act does not authorize code or
   narrow #16009.
2. Run D1; only a complete K1 pass permits the identical-source D2
   confirmation. Failure kills route (b); no scope act or implementation
   follows.
3. After D1/D2 pass, ensure S1–S6 from landed plan §10 have recorded
   owners/issues or explicit dispositions, and file the proposed
   S7–S11 successors in §7.3 before any scope act. The owner records
   route (b) as partial and keeps original acceptance open until every
   required leg is met, unless it explicitly revises acceptance; the
   geometry-only candidate does not pass the current decisive check.
4. Any scope act must publish the exact retained/deferred facts, the
   full cell disposition for C1–C35, successor ownership, and that
   §6.1 was not adopted; known-SYN-frag/Q1 transfer only under that
   act. Class-R must confirm retained matches drop as configured and
   all unaffected local/control packets still follow
   `pass_local_control`. A later code change invalidates the
   source-pinned measurement; implementation still owes the dual-stack
   gate.

### 7.3 Proposed successor issues under route (b) (acceptance sketch)

The following are proposed new successor issue sketches, not issues
filed by this design. S1–S6 retain the requirements in landed plan
§10; the adopting owner must confirm their issue/owner status or
record explicit dispositions before a scope act. Each new successor
must carry G1/pre-G1 evidence, independent K1-equivalent acceptance
for its enforcement layer, and a prohibition on claiming #16009 parity.

- **S7:** `shim: enforce deferred TCP flag screens on host-bound kernel-PASS paths` — owner: userspace-xdp shim + Go mask/ABI maintainers. If known-flags SYN-frag or Q1 transfers by explicit scope act, acceptance requires separately pinned clean-room shapes (no TCP-1 `off=56` substrate) and complete-object K1 for the selected fact(s), plus C5 known-SYN-frag and the re-plan §6.2/§7.2 Q1 artifacts (C23's 128 outcomes and URG|ACK-to-443 control; C22's no-flag leg; C26/C35 Q1 legs; conservative-row Q1 bits). Any fact not transferred remains in #16009; §6.1 is not adopted.
- **S8:** `shim: IPv4 source-route and malformed-options facts for
  host-bound kernel-PASS traffic after V4-1 link failure` — owner:
  userspace-xdp parser maintainers. Acceptance: legal IPv4 options
  extraction under a clean-room protocol with no known-failing
  substrate, or qualified route-(a) redirects for every required
  affected arm with all excluded arms explicitly assigned, or a
  worker-side ownership decision with complete coverage proof; C2/C20
  cells remain the oracle.
- **S9:** `shim: IPv6 fragment geometry and extension facts after V6-1 cap failure` — owner: userspace-xdp walker maintainers.
  Acceptance: each new walk fact independently measured in a
  substrate-free complete object (not analogized from the fragment
  precedent), or qualified route-(a) redirects for every required
  affected arm with all excluded arms explicitly assigned, or
  permanent worker-side ownership with complete coverage proof;
  C7/C21 and the IPv6 fragment-geometry cells are the oracles. Any
  scratch-channel proposal must address the +298,128 precedent.
- **S10:** `shim: TCP tiny-declared/capture-unknown screen facts —
  stack adjudication in a substrate-free measurement` — owner:
  userspace-xdp parser maintainers. Its own separately authorized
  protocol must isolate only the tiny/capture family on the pristine
  baseline, exclude TCP-1's changed `off=56` substrate and every other
  known-failing delta, include C22's pointer-valued-end witness and C6,
  and adjudicate both per-frame and combined-chain stack ≤512 B plus
  complete-object K1. This design allocates no TCP run; no tiny/capture
  claim is made until S10 passes.
- **S11:** `screen: enforce ICMP-fragment checks on host-bound kernel-PASS traffic outside the geometry-only route` — owner: userspace-xdp shim + userspace-dp worker maintainers. Acceptance: C3's IPv4/IPv6 ICMP-fragment vectors and nonfragment/atomic controls on every required local-PASS arm, with configured per-zone disposition and counters; or a qualified worker redirect/nft path that proves each required arm and assigns excluded arms explicitly. Any shim shape is measured clean-room without unrelated failed facts. No ICMP-fragment claim is made until it passes.

S1–S6 remain unchanged from landed plan §10. Flood rate meters remain
nft's and are not substitutes for malformed-packet successors.

---

## 8. Bounded measurement protocol for route (b)

This proposal allocates **two of the nine remaining** fit-design runs:
D1 is run 5 of 13; D2 is run 6 of 13 and occurs only if D1 fully passes.
Runs 7–13 remain unspent. A three-seat act must authorize the pair
before execution; this text authorizes no code, run, or scope change.
The exact G1 base is `7e4b3d2e3b32cde9a9cba617f58d7e40ac14bbb1`.
Use the pinned G1 command and environment (`g1-results.md:30-35`):
`CARGO_TARGET_DIR=/var/worktrees/.cache/cargo-16009 TMPDIR=/var/worktrees/.cache/tmpdir GOTMPDIR=/wtgt GOCACHE=/var/worktrees/.cache/go-build XPF_SHIM_ALLOW_LOW_HEADROOM=0 make generate-userspace-xdp`.
Each run uses a fresh detached scratch worktree at that base and a
complete source pin: tracked diff plus every untracked/shared file's
hash, along with toolchain and command inputs (`6675582825`). Never
install the generated object. If a necessary build input has changed
from the recorded G1 base, stop and seek a separately authorized
changed-input baseline; do not silently substitute `master`.

### 8.1 Clean-room construction rules (the GLM residual, made binding)

Each rule below is mandatory. A host-corpus failure before a generation
command spends no verifier run; once the pinned generation command is
invoked, the run is charged regardless of whether compilation, linking,
or kernel verification is the first failing stage.

- **CR1 — Baseline plus one delta.** Start from the pristine G1 base
  and add only the retained-fact geometry gate. Do not reuse G1's
  mixed arm worktree or include another arm's fact code. In
  particular, do not reproduce TCP-1's changed substrate that yielded
  `off=56`, V4-1's TLV selector, V6-1's carried walk state, or any
  other measured-dead or unmeasured arm delta. This construction rule
  does not remove or rewrite unrelated baseline behavior.
- **CR2 — One candidate only.** The measured shape is the complete
  baseline object plus the geometry word/gate/map integration at all
  11 selected terminal arms. It contains no new `ExtWalk` outputs,
  IPv6 fragment geometry, ICMP-fragment/SYN-fragment facts, IPv4 TLV
  parser, TCP tiny/Q1 facts, or redirect classifier. No arm is priced
  by composing partial counts.
- **CR3 — Link and all earlier stages consume the invocation.** Link
  failure is recorded as a link disposition with no insn/stack
  verdict, but the generation invocation is still charged. V4-1
  establishes that link precedes kernel verification; it does not
  establish that a link failure is free budget.
- **CR4 — Host corpus before each invocation**, on the exact pinned
  source: positive IPv4 POD `>` 65535 and `=` 65535 controls; teardrop
  zero/short/MF nonmultiple/legal-last. IPv4/IPv6 ICMP-fragment,
  known-flags SYN on first fragment, atomic/non-first IPv6 fragment,
  governing-header, and clean-packet cases are non-trigger controls:
  the candidate emits no decision for those facts. The corpus tests
  only the retained IPv4 geometry; it does not assert other coverage.
- **CR5 — Strict sequence.** Run D1, record its complete disposition,
  then and only if it passes authorize D2. No parallel dispatch or
  retries.
- **CR6 — Fixed ceilings.** Before D1, record K1 unchanged: complete
  object ≤850,000 processed instructions, floor PASS (≥15% headroom),
  `override_consumed: false`, and an actual stack adjudication of
  every frame and combined chain each ≤512 B. Chain sums from an
  aborted run are not stack verdicts.

### 8.2 Runs (maximum 2 of the remaining 9; 7 remain held)

| Run | Shape | Gate it decides |
|---|---|---|
| **D1 — run 5 of 13** | Full geometry candidate from CR1/CR2, built and verified as one complete object | Diagnostic existence test. PASS only if every K1 condition in CR6 passes; compiler/link/access/cap/stack failure or any K1 threshold miss kills route (b). |
| **D2 — run 6 of 13** *(only after D1 PASS)* | Identical-source confirmation build; all component and untracked/shared hashes must match D1 | Completes K1 confirmation. Any result other than full K1 PASS, or source mismatch, kills the candidate pair. |

Runs **7–13 remain held** for a new three-seat act. This protocol
contains no zero-cost link preflight, no TCP diagnostic, no reserve
recomposition, and no retry.

Explicitly not in this allocation: V6-2R/V6-3, V4-2/V4-3, TCP-2/TCP-3
(preconditions false, §2.3); any changed build-input baseline; any
deferred fact or route-(a) classifier; Class-R or landing activity.
After a separate implementation authorization, Class-R and dual-stack
smoke remain required as specified in fit design §8 step 6.

### 8.3 Stop rules

1. **First failure stops.** Any compile, link, access, cap, stack, floor,
   override, corpus, or source-pin failure stops this route's protocol;
   D2 is not run after a D1 failure.
2. **No unchanged retries or silent shape changes.** D2 is only the
   prescribed confirmation of a passing D1. A fix, source delta,
   localized predicate removal, or changed base requires a new
   three-seat act and budget decision.
3. **Hard budget stop.** The protocol ends after D2 or earlier on
   failure. It spends at most 2 of 9 remaining runs; runs 7–13 stay
   held and cannot be consumed by this design.
4. **Deviation stop.** Any departure from CR1–CR6 voids the affected
   evidence; the invoked generation run remains charged. No generated
   object is installed.

---
## 9. Kill criteria (pre-registered)

Route (b) is killed — and the comparison reopens on the resulting
evidence — if any of the following holds:

1. **Candidate kill:** D1 fails any stage or K1 condition (compile,
   link, access, instruction ceiling, floor, override, or adjudicated
   per-frame/combined stack), or fails the host corpus. This kills
   this complete geometry candidate only; it does not prove every
   shim design impossible and does not automatically select route (c).
2. **Confirmation kill:** D2 fails any K1 condition or D1's complete
   source/toolchain inputs cannot be reproduced exactly.
3. **Boundary kill:** retaining §5.2 facts requires widening
   `ParsedPacket`/`ExtWalk`, changing `MAX_EXT_HDRS` or walk
   advance/break rules, adding a walk output or packet read, or
   gating transit / omitting any of the 11 arms. That is a new
   proposal, not the measured route (b).
4. **Scope kill:** the owner will not record route (b) as a partial
   remediation, enumerate deferred successors, and keep the original
   acceptance open (or explicitly revise it) before implementation.
   Without that act, no code lands under a geometry-only claim.
5. **Honesty kill:** any artifact claims source-route, duplicate-
   fragment, malformed-options, ICMP-fragment, known-SYN-fragment,
   IPv6-geometry, tiny/capture, Q1, overlap, scan/sweep, cookie, or
   claimed-zone parity before its assigned successor passes; cites 632 B
   or 640 B chain sums as stack adjudications; or treats a partial
   count (30,275; 99,774–101,488; 1,000,001) as a cost or a pass.
6. **Budget kill:** this protocol spends more than runs 5 and 6, retries
   an unchanged shape, or runs a §2.3-dead shape. Any extra run or
   changed-input baseline requires a new three-seat act.

Route (a) is killed as an escalation candidate if its §4.5 acceptance
cannot be specified per arm, its superset membership cannot be proved
exhaustive for the selected arms, or no owner accepts an explicit
worker-absent/overload policy. Route (c) requires three-seat
convergence on plan-kill plus §6.2's successor assignment; neither a
route-(b) failure nor budget exhaustion adopts it by default.

---

## 10. Evidence that would change the recommendation (what would flip it)

Each item names the evidence and the route it selects. A seat holding
such evidence overturns §1 by producing it.

1. **S10 clean-room evidence:** an independently authorized tiny /
   capture shape, built on the pristine base without the TCP-1
   substrate, has per-frame and combined-chain stack each ≤512 B and
   a complete-object K1 pass. → Seats may reconsider whether those
   facts can join a later shim scope act; this protocol spends no TCP
   run and this alone does not revive source-route or walk facts.
2. **Measured walk-fact extraction:** a substrate-free complete
   object transports the exact IPv6 fragment-geometry, Routing, or
   duplicate fact at ≤850,000 with K1 stack adjudication. → The
   corresponding S9 fact may be reconsidered under a new scope act;
   an isolated slice, host-only test, or analogy to +298,128 does not
   meet the bar.
3. **Measured IPv4 options path:** a legal source-route/malformed-
   options extraction shape both links and passes verifier access on
   its own, then satisfies complete-object K1 without embedding a
   known-failing substrate. → S8's shim path may be reconsidered;
   link/access acceptance alone is not a complete-object fit.
4. **A complete route-(a) package:** source census, worker-path tests,
   worker absent/overload contract, and complete-object classifier
   measurement satisfy §4.5. → Re-score route (a) against (b); it
   supersedes (b) only if it proves wider required-case coverage and
   the owner accepts its availability trade.
5. **Proven nftables enforcement:** concrete rules and packet tests
   establish the original decisive local-address regression, required
   hooks/fragment visibility, and per-zone counters. → An nftables
   successor becomes a serious route-(c) alternative; existing flood
   meters alone are not such evidence.
6. **Owner withdrawal of acceptance:** the issue owner explicitly
   withdraws the decisive overlapping-fragment / LSRR / ICMP-fragment
   local-address check and every other requirement not assigned to a
   successor. → An accept-risk successor becomes admissible; without
   that recorded withdrawal, #16009 remains open for the residuals.
7. **Kernel/toolchain change:** a verifier, bpf-linker, or pinned
   toolchain change is shown to legalize a previously measured-dead
   shape by re-running that recorded shape under its own authorized
   protocol. → Its successor may be reconsidered; it does not
   retroactively alter G1 or the scope boundary.
8. **D1 candidate failure:** any D1 failure kills route (b). Seats
   compare route (a) and (c) using that evidence; a non-localizing
   cap/stack result also kills the route but does not prove every shim
   design impossible or automatically select plan-kill.

Absence of these items is the current state of the record. The
recommendation in §1 is made on that record, under §3's censoring
and non-additivity limits, and under the standing prohibitions:
no override, no silent narrowing, no partial count cited as a pass,
and no claim that §6.1 was adopted or that any rank-2/3 shape was
measured.

---

## Appendix A. Source map (so reviewers can check every load-bearing claim)

| Claim in this document | Source |
|---|---|
| G1 final dispositions; budget 4/13, 9 remain; G2 diagnostic-killed; §6.1 NOT adopted; V6-2R/V6-3/V4-2/V4-3/TCP-2 preconditions false; GLM substrate residual carried forward | Issue #16009 `issuecomment-6675710585` (parent final) |
| Baseline 779,213 reused-not-rerun; per-arm logs, signatures, hashes; host corpora PASS; order chronology; no-install verification | `/var/worktrees/campaign-drive/g1-results.md:3-35,67-257,273-314` |
| TCP-1 = gate failure by access, mechanism/stack unjudged; no auto-selection of TCP-2 from the 632 B sum | `issuecomment-6675614112` (Kimi, accepted), `6675500896` (Sol), final record `6675710585` |
| G2 unbuildable a priori (V4-1 in the exact set); component-hash pinning guardrail | `issuecomment-6675582825` (GLM), parent ruling `6675609580` |
| K1 definition (≤850,000, floor PASS, override false, complete-object only); 13-run budget; failure-signature routing; stop rule | Fit design §§1, 8; landed plan §9-K1 |
| Sink-only 755,620 PASS; pre-G1 deaths (`off=34/35/56`, 528 B stack, cap variants with state counts) | Fit design §3; re-plan §3.1 |
| +298,128 measured laundering precedent; second-walk-value state-merging mechanism | Landed plan §5.1 (`lib.rs:588-602`); fit design §2 item 1 |
| 11 arms, insertion anchors, transit exclusion, two pre-parse CPUMAP exclusions | Landed plan §1 (`lib.rs:612-618,2138-2146` and arm table) |
| `pass_local_control` intentional on degraded/ctrl-disabled arms; redirect contract breakage | Landed plan §2.1 (`lib.rs:1812-1816`); `userspace-xdp/src/lib.rs:891-894,1671,1726-1728,1812-1816` on master |
| XSK redirect tail, `binding_slot_ready`, `UserspaceDpMeta` | `userspace-xdp/src/lib.rs:257-289,896,1177-1300` on master |
| Worker stage-10 entries; flow/flowless TCP-screen asymmetry | Landed plan §1 (`screen/mod.rs:912,1232-1276`); `userspace-dp/src/afxdp/poll_stages.rs:1100ff` |
| Retained IPv4 geometry inputs; deferred IPv6 `ExtWalk` fields | Landed plan §4 table / §5.3 packing list (`lib.rs:2292-2355`); `ipv6_ext_walk.rs:191-226,308-343` |
| S1–S6 requirements/owners and conditional prior S7 planning title | Landed plan §10 |
| Q1 acceptance artifacts available for a newly scoped S7 | Re-plan §§6.2, 7.2 |
| nft flood meters exist and are out of scope; IPv4 prerouting fragment-visibility constraint on nft placement | Landed plan §1 (`host_inbound_screens.go`); `pkg/nftables/netlink_lo0.go:30-34` |

## Appendix B. Non-goals of this document

No production code, no test change, no verifier or generation run, no
edit to the landed plan / fit design / re-plan / implementation
worktree, no scope amendment to #16009, and no filing of proposed
successors S7–S11 or plan-kill sketches PK-W/PK-N/PK-R. Any filing
or scope act requires a separate recorded decision after review and
route selection; the proposals here are planning only. Numbers herein
are transcriptions of, and arithmetic on, the G1 record and pre-G1
matrix (§2–§3); the primary records govern on any discrepancy.
Throughput or performance claims from instruction counts are
prohibited (multiple seat records); none is made.

*End of step-0 design.*
