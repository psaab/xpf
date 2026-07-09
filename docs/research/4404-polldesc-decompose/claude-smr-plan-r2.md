# Claude SMR — Hostile Plan Review R2 (CONVERGENCE): #4404 poll_descriptor decomposition

Reviewing plan.md (v2) after Codex R1 (`task-mrdxqm0z-83tr4r`, VERDICT PLAN-KILL).
AGY infra-down this session → 2-of-3 convergence (Codex + Claude-SMR).

## VERDICT (R2, CONVERGED): PLAN-KILL

I reverse my R1 "PLAN-NEEDS-REVISION → READY". Codex's R1 refutation is
**correct and dispositive**, and I **independently verified each load-bearing
claim against `origin/master` `03a92b49c`** before accepting it (I do not
rubber-stamp a co-reviewer any more than the author). My R1 accepted the plan's
premise that the three arms are "cold by construction" (my R1 F4). **That premise
is false**, which invalidates the entire cold-arm-scope PLAN-READY.

## The dispositive error I missed and Codex caught: the arms are NOT cold

- **FLOWLESS is a per-packet path, not an exception.** The flow-cache fast path
  requires `Some(flow)` (mod.rs:867-869: `packet_eligible(meta) && let Some(flow)
  = flow.as_ref()`). Non-first IP fragments and non-query ICMP **deliberately
  have `flow == None`** (poll_stages.rs:458-470, #3064/#3902). Therefore *every*
  fragmented / no-L4 packet enters the FLOWLESS arm at mod.rs:3581. Fragmented
  traffic (MTU-mismatch UDP, tunneled/IPsec inner fragments, jumbo flows) is a
  **sustained line-rate workload**, not a rare edge — so `inc A` would put a new
  `#[inline(never)]` per-packet `call` on it. **Verified.**
- **SESSION-MISS is amortized-hot under deny-flood / at-cap.** Denied traffic
  and session-cap refusal install nothing (mod.rs:2968 `note_admission_refused`
  + rollback; mod.rs:3469 deny/reject branch) and **re-run the full arm on every
  packet**. SYN/deny floods and at-cap operation are exactly the DoS conditions
  where the dataplane must not regress. **Verified.**
- **MissingNeighbor repeats per-packet while the neighbor is unresolved.** First
  packet installs `MissingNeighborSeed` (mod.rs:5101); subsequent packets
  re-resolve and return to the same arm (the arm documents duplicate-drop /
  per-packet repetition). **Verified.**

This is the **#1697-v1 / #4409(b) failure mode exactly**: outlining a
repeated-path body into `#[inline(never)]` forces a per-packet `call` (+ meta
copy / spill) — here on the *fragment*, *DoS*, and *unresolved-neighbor* paths,
which are both real and the worst places to regress. My R1 F4 was wrong.

## Codex's other findings I verified and accept

- **The asm gate is not executable as specified.** Installed `cargo-asm` 0.1.16
  is recorded as panicking on this repo's symbols (session_glue/promote.rs:15).
  My R1/F5 "inline-never capture pin" fallback **invalidates the measurement** —
  pinning the loop fn changes the caller boundary / frame / regalloc being
  measured. #1697 used `nm` + linked-binary `objdump` on **two named guarded
  branches**, not a generic unnamed-basic-block diff of a 4,796-LOC symbol. The
  plan's gate would also inspect only cache-hit + FORWARD-BUILD blocks and thus
  **miss** the new FLOWLESS/MissingNeighbor per-packet calls. **Verified.**
- **The loop IS unit-testable — my §9 "un-callable in isolation" is false.**
  `txn_run_descriptor` (tests.rs:7672) builds test UMEM/XSK state and invokes the
  real `poll_binding_process_descriptor` (7773); existing tests assert on
  `scratch_recycle` (tests.rs:7952, 11691). Exact-count recycle assertions are
  therefore *achievable* — which both removes the plan's excuse for smoke-only
  gating **and** means the plan mischaracterizes the test surface it must build.
  **Verified.**
- **`ArmOutcome` mis-models the fall-through accounting.** mod.rs:5375
  `recycle_now=false` (PendingNeighAdmission::Buffer) **falls through** to the
  debug block and `record_forwarding_disposition` (5412) — it does not
  `continue`. My R1 `Handoff => continue` mapping would skip that accounting =
  behavior change. **Verified.**
- **Signatures are not compilable.** `PacketCtx.decision` cannot be a ctx field
  passed *into* the arms — `decision` is the *result* of the 965-3868 expression
  the arms produce. `resolve_session_miss` omits `XdpDesc`/`area`/`raw_frame`/
  `packet_frame`/`binding_index`/`ingress_zone_override`/`packet_fabric_ingress`;
  `handle_missing_neighbor` is reachable with `flow == None` (mod.rs:4628) so
  `&SessionFlow` is wrong; `packet_frame` (900) may borrow `owned_packet_frame`,
  a self-borrow that folding both into one `&mut PacketCtx` breaks. **Verified.**
- **#1697 is not the value/safety precedent I claimed.** #1697 was *pure motion*
  of already-factored standalone fns with unchanged call sites and borrows. This
  proposal rewrites 23 terminal drop-exits, invents a control-flow protocol, and
  forces calls on repeated paths — categorically riskier. **Accepted.**

## Why this is PLAN-KILL, not PLAN-REVISE

The plan's *only* safety argument was "the arms are cold, so `#[inline(never)]`
is free." With that false, every proposed arm-level seam sits on a real
per-packet path, and there is **no executable codegen gate** that both runs on
this repo's tooling and inspects those paths. What remains after removing the
unsafe moves is exactly what already shipped in #1697 (cold *leaf-body*
outlining) — not the *arm decomposition* this issue asks for. The residual
`poll_binding_process_descriptor` is the **irreducible per-packet RX dispatch
core**: its "phases" are branches of one `let mut decision = if…else` expression
sharing the validated packet pointer, `decision`, the scratch buffers, and
session/worker state under NLL borrows, several of which (FLOWLESS,
MissingNeighbor, flood-SESSION-MISS) execute per packet. There is no clean,
codegen-neutral, behavior-preserving arm seam.

This converges with the project's standing verdicts on the sibling hot-path
god-functions: **#4409(b) PLAN-KILL** (extract-target turned out amortized-hot)
and **#4408 PLAN-DEFER** (residual is the irreducible hot build-dispatch). #4404's
arm decomposition is the same class and gets the same answer.

## Converged recommendation
**PLAN-KILL the arm-level decomposition.** The genuine residual value
(navigability of a 4,796-LOC fn) does not clear the bar of *ungated per-packet
codegen risk on the fragment / DoS / unresolved-neighbor paths* plus
behavior-changing control-flow surgery. Any future revisit must (per Codex §7):
target only genuinely-rare/heavy *sub-bodies* (not whole arms), ship
compile-proven staged signatures, add `txn_run_descriptor`-based **exact-one-
owner recycle unit tests**, produce linked-binary `nm`/`objdump` artifacts with
reproducible named anchors, and set **quantitative fragment / unresolved-neighbor
/ new-flow pps thresholds** — a materially different (and much narrower) piece of
work than this issue as filed. Label `plan-kill`; close.
