# Claude SMR — hostile plan review r3 (#5837)

**Verdict: PLAN-READY.** v3 folds Codex r2's spec-depth findings into a concrete,
implementation-ready design and fixes the three factual errors it caught. I re-checked
each and confirm the fixes are correct.

## Codex r2 dispositions — verified
- **ICMP contract (was wrong) → fixed correctly.** `parse_l4` returns `flow_dst_port = 0`
  for ICMP/ICMPv6 (lib.rs:1516). So an ICMP intent published with `dst_port = 0` hits via
  an **exact** probe on `(proto, ip, 0)` — no runtime identifier, no wildcard. v3 §5a
  states this. The v2 "identifier convention" claim is gone.
- **Fixed capacity (was "sized to config").** v3 §5c uses a fixed compile-time
  `max_entries = 8192` + a commit-time cardinality preflight — matches how BPF `MapSpec`
  capacity actually works (fixed at load). Correct.
- **AH/IKE control-flow (was wrong) → fixed.** §8.6 now says the shim short-circuits
  ESP/non-native-GRE/WG only (lib.rs:539-548), and AH/IKE terminate via the helper's
  IPsec stage before its DNAT (poll_descriptor:823 vs :1511). Matches the code.
- **Availability test (was impossible) → fixed.** §10 now bounds/counts `slow_path_drops`
  rather than asserting delivery under exhaustion (which `slow_path.rs:283` makes
  impossible). Correct framing.
- **No-silent-bypass (Codex's strongest point) → discharged well.** §5d makes a
  **mandatory operator-visible commit warning** for every form the intent map doesn't
  dataplane-enforce. This is the right resolution: a High-severity fix must not leave a
  config form silently marked-fixed — now every residual is loud.
- **Atomic reconcile / all activation paths / startup gating.** §5b + §5d specify
  insert-all-rollback-on-fail before the generation swap, hook every activation path, and
  — cleanly — observe that an empty intent map degrades to *today's* behavior, so the
  startup window is the status quo, not a new bypass. That neatly answers "gate until
  authoritative."
- **Only-translating rows, over-steer framing, canary allowlist, native-endian key,
  cross-side test, v4-only↔PLAN-KILL ladder, 6.18-floor+current-image** — all present.

## Is v3 a *research* deliverable or an *implementation*?
v3 is now quite prescriptive (concrete structs, wiring checklist, FD plumbing). That is
appropriate here: this is a shim-ABI + multi-writer-map change where the failure modes
are all in the wiring details (byte-order, collision, atomicity, ABI rollout), so a plan
that hand-waved them would be unreviewable. The design is fully specified and bounded;
the one irreducible unknown remains the verifier verdict, which has an explicit ladder
and fail-safe.

## Residual (non-blocking, implement-time)
- The §5d commit warnings are new operator-facing strings — ensure they're worded so an
  operator can act (which rule, why not enforced, what to change). Doc/UX detail.
- Instruction-reclaim (ladder step 5) is still described by area, not a concrete refactor
  — acceptable as a fallback branch that's only entered if v4-exact-only rejects, and
  which would itself be re-verified.

## Bottom line
v3 closes every Codex r2 finding with correct, code-verified fixes and discharges the
no-silent-bypass requirement via mandatory loud diagnostics. The design is sound,
bounded, and implementation-ready, with the verifier as the defined first implement-time
gate and a PLAN-KILL/scope-reduction fork. **PLAN-READY.**
