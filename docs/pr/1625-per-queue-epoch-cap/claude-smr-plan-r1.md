# Claude SMR plan-review r1 — #1625 per-queue epoch-cap

Reviewer role: domain SMR — CoS scheduler / token-bucket math /
WFQ-class scheduling theory / Junos guarantee-rate semantics.
Hostile in-conversation review of plan v1.

Verdict: **PLAN-NEEDS-MINOR** (one structural concern, one wording
nit, one diagnosis gap. None block proceeding to implementation
contingent on Codex + AGY both agreeing.)

## Findings

### MAJOR-DOWNGRADED-TO-MEDIUM: The diagnosis in §2 is plausible but unverified

The plan asserts that today's selector visits large queues
fast enough that "every queue is visited within 200 µs" and
therefore each queue accumulates enough tokens between visits to
drain its quantum. This is a hypothesis with strong supporting
geometry (one selector call ≈ ns, RR over 11 queues ≈ µs, well
under 200 µs) but NO direct trace evidence.

What I'd expect a hostile reviewer to demand:
- A short journalctl/perf trace from the loss userspace cluster
  during the PR #1618 smoke showing the actual per-class visit
  cadence and per-visit `secondary_budget`. Without it the
  diagnosis is theory; PR #1625 might ship and STILL fail Pass C
  because the real bottleneck is elsewhere (e.g., the upstream
  AF_XDP RX queue distribution funnels all classes' traffic
  through one binding's tx queue, in which case per-binding
  per-queue caps multiply by N bindings and don't bind globally).

**Recommended mitigation before round-2 PLAN-READY**: add a
deliberate §2.1 "Empirical evidence" subsection citing whatever
hot-path counters or per-class TX-byte deltas the existing
telemetry exposes, OR explicitly call out that the diagnosis is
unverified and the smoke is the final arbiter. Plan §9 risk 1
already acknowledges this — that's defensible. Bump to MEDIUM.

### MEDIUM: §4 cross-binding-skew limitation is real but understated

The plan's §4 acknowledges that with N bindings each owning some
fraction of a class's traffic, per-binding caps multiply: 2
bindings = 2× effective rate, etc. The smoke fixture pins each
class to a single sender (so one RSS hash → one queue → one
binding) — so this works.

But §9 risk 5 says "Acceptable for PR-1625 because the smoke
fixture pins each class to a single binding." This is true for
the **synthetic** smoke harness, but the documentation update in
§6 to `docs/fairness-regimes.md` claims "the algorithm is now
functional" — operators will read that as "guarantee-rate now
works in production". If a real customer's traffic pattern hits
N bindings per class, guarantee-rate is **broken**, not merely
"capped at N×rate". I want the docs change to explicitly call
out the per-binding-cap caveat. Otherwise this is a footgun.

**Recommended**: add to §6 an explicit doc-update line
documenting "guarantee-rate enforces per-queue rate caps
per-binding; in deployments where multiple bindings see traffic
for the same class, the effective per-class cap is N×rate where
N is the binding count carrying traffic for that class." This is
operator-visible truth.

### MEDIUM: Floor at COS_GUARANTEE_QUANTUM_MIN_BYTES interacts with rotation

Consider a queue with `rate × 200µs = 800 B` (a 32 Mbps class).
The allowance floors to 1500 B. So in epoch N the queue is
allowed 1500 B; if it has been visited once this epoch and the
first head packet was 1500 B, `epoch_bytes_serviced = 1500`,
which equals allowance → next visit in this epoch is skipped
correctly. Good.

But the floor effectively bumps the queue's enforced rate to
`1500 / 200µs = 60 Mbps`. The plan acknowledges this in §9.2 as
"documented limitation". That's fine for the smoke (100 Mbps
minimum class). It is NOT fine for any operator who configures a
10 Mbps class and expects 10 Mbps. **The Junos contract for
`transmit-rate exact` is rate enforcement**. Letting a 10 Mbps
class drain at 60 Mbps because we floored is a deviation.

**Two paths**:
A. Accept the floor, document it, **add a config-time warning**
   when a configured rate × 200 µs is below the floor. The
   warning can suggest the operator reconfigure or accept
   over-share. (Adds ~30 lines of config validation in
   `pkg/config/compiler_class_of_service.go`.)
B. Don't floor in `cos_per_queue_epoch_allowance_bytes`; let
   the allowance compute to e.g. 800 B; the first visit's
   `head_len` (likely 1500 B+) will exceed allowance after
   debit → next visit in this epoch skipped. Net effect: queue
   visited 1× per epoch, drains 1 packet, achieved rate ≈
   `MTU / 200 µs = 60 Mbps anyway` (because we don't fragment).
   Same effective rate as path A. Conclusion: the floor is a
   no-op when allowance < `head_len`.

**Recommendation**: REMOVE the floor in
`cos_per_queue_epoch_allowance_bytes`. Let allowance compute
honestly. The first-visit overshoot is bounded by `head_len`
(MTU + framing) which the scheduler can't avoid without
fragmenting. Update §9 risk 2/3 to reflect that this is a
**physical MTU constraint, not a mechanism choice**.

(MEDIUM, not MAJOR, because the floor isn't catastrophically
wrong — it just lies about being a mechanism choice when it's
really a no-op.)

### MINOR / NIT: Plan §3 helper signature

The plan defines
`cos_per_queue_epoch_allowance_bytes(queue, guarantee_fraction)`
but then writes "PROVISIONAL PICK: always cap at exactly rate ×
epoch (ignore frac in the per-queue cap)". If we ignore the
fraction, the helper signature should drop it:
`cos_per_queue_epoch_allowance_bytes(queue)`. Minor wording fix.

### NIT: Test 8.1 #3 ±5% tolerance under stochastic
`now_ns` sweep is too tight given 1500 B floor + MTU rounding.
Suggest ±10%, OR drop test #3 from the cargo set (Pass C smoke
is the real test).

## Checklist verification

- [x] §1 scope is clean and explicitly file-zone disjoint with
      #1622 and #1623 sub-agents.
- [x] §2 diagnosis is plausible (one MEDIUM, see above).
- [x] §3 mechanism is sound. Per-queue per-epoch cap with
      timer-based rotation is the standard WFQ-class enforcement
      pattern. Owner-only single-writer matches the codebase
      discipline.
- [x] §4 cross-binding picked correctly (per-binding, not
      shared). One MEDIUM doc-warning ask.
- [x] §5 arithmetic is overflow-safe (u128 intermediate).
- [x] §6 file list looks complete. Confirm by inspection:
      `types/cos.rs`, `cos/builders.rs`, `cos/queue_service/mod.rs`,
      and the test initializers. Verified via grep that
      `CoSQueueHotState` and `CoSInterfaceRuntime` literals exist
      in `worker/cos/tests.rs` (7 hits) — yes the plan accounts
      for them.
- [x] §7 perf overhead is negligible. Verified.
- [x] §8 test plan covers the 4 invariants (cap-limits-large,
      reset-at-boundary, honors-small-with-oversub,
      proportional-mode-unchanged) plus the BLOCKING Pass C smoke.
- [x] §9 risks are honest. The risk-1 admission is appropriate
      given the unverified diagnosis.
- [x] §10 open questions ARE genuinely open (not rhetorical) and
      provide PROVISIONAL picks the reviewers can challenge.
- [x] §11 PLAN-KILL conditions are concrete and testable.

## Approval contract

I will MERGE-READY this plan after these MEDIUM findings are
addressed in plan v2:

1. Add §2.1 explicit "Empirical evidence" subsection OR strengthen
   §9 risk 1 to be explicit that the diagnosis is theory and
   the smoke is the final arbiter.
2. Update §6 docs-update line to include the per-binding-cap
   caveat in `docs/fairness-regimes.md`.
3. Remove the `COS_GUARANTEE_QUANTUM_MIN_BYTES` floor in
   `cos_per_queue_epoch_allowance_bytes`; update §3 + §9.2/9.3
   to reflect "first-visit overshoot bounded by MTU, not by the
   floor".
4. Update helper signature in §3 to drop the unused
   `guarantee_fraction` arg per PROVISIONAL pick in §10.4.

NITs (test #3 tolerance) are non-blocking — discretionary.

## Bottom line

The plan is structurally sound. The mechanism is the right one
for the diagnosed root cause. The main risk is that the
diagnosis itself is wrong — and the plan handles that via the
PLAN-KILL conditions in §11 and the Pass C blocking smoke gate
in §8.6. With the four MEDIUM fixes above, this is ready for
implementation.
