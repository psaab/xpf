# Claude SMR — hostile plan review r2 — #6177

Re-review of `plan.md` r2 (@ 618451f9a434). Checking the SMR-1..7 fixes landed and
hunting for NEW holes.

## r1 finding disposition

- **SMR-1 (benign independent of δ_remove)** — FIXED. §3 now labels the µs/ms figures
  "illustrative, not load-bearing"; §4 adds an explicit magnitude-independence
  paragraph (even the ~1 s failed-removal case is masked). The measurement objection
  no longer bites.
- **SMR-2 (security threat model)** — FIXED. §3 adds a threat-model paragraph:
  not attacker-triggerable, transient duplicate-ARP, dual-active forwarding already
  fenced by #5640's rg_active gate. The `security` label is addressed head-on.
- **SMR-3 (fabric best-effort)** — FIXED. §3 now qualifies `tryPrepareUserspaceRGDemotion`
  as best-effort/ordered-before with a `Warn`+proceed fallback and names the fallback
  harm (brief TCP-recoverable loss).
- **SMR-4 (Option-A hybrid)** — FIXED. §5 Option A now rebuts the on-success/on-failure
  hybrid explicitly (attempting-first IS the reorder; taxes every good case, buys
  nothing on the failed case).
- **SMR-5 (Residual-2 YAGNI)** — FIXED. §6 weighs YAGNI vs the case-for and offers
  dropping Residual-2 as a defensible narrower scope (§11 Q-b).
- **SMR-6 (smoke is a gate)** — FIXED. §8/§9 state the smoke is a regression gate, not
  a window measurement.
- **SMR-7 (#5640 invariant)** — FIXED. §8 names `SetRGActive(false)`-before-
  `signalFailoverActuated` as an invariant the /engineer PR must not disturb.

## New hostile probes on r2

- **Probe A — does the plan over-claim that #5482 fully neutralizes the failed-removal
  window?** #5482's reconcile is bounded to 5 attempts (`vipRemoveReconcileMax`,
  instance_vip.go:17) at 200 ms backoff; on exhaustion it logs Error and leaves the
  VIP. So there is a pathological tail (netlink wedged >~1 s) where the stale VIP
  persists until the next transition. The plan should not imply #5482 is a hard
  guarantee — but this does NOT change the recommendation: (i) it is a pre-existing
  #5482 property, not introduced here; (ii) the ack-barrier levers under debate do
  nothing for it either; (iii) it is still masked for transit by rg_active/fabric.
  Verdict impact: none, but §3/§4 wording "cleared within ~1 s" should read
  "typically within ~1 s (bounded reconcile; pathological netlink wedge logs Error
  and defers to the next transition)". MINOR wording nit, not a blocker.
- **Probe B — is `make test-failover` even the right smoke, given nothing changes on
  the failover timing path?** Yes — CLAUDE.md mandates it for any pkg/daemon HA touch,
  and it is the cheapest guard that the barrier signature refactor did not perturb the
  demotion branch ordering. Correctly scoped as a gate.
- **Probe C — could dropping Residual-2 (per Q-b) leave the Residual-3 tests asserting
  behavior that the un-hardened code does not provide?** No — the Residual-3 tests
  cover arm/signal/wait/timeout/cleanup, which the current barrier already provides;
  only the identity-checked-disarm test is Residual-2-specific. So Q-b's "drop #2,
  keep #3" is internally consistent (drop just that one test with it). Plan is
  coherent on this.

No new blocking hole. The core recommendation (PLAN-KILL Residual-1 code change; land
#2+#3+doc, with Q-b flexibility) is firsthand-sound and I could not break it across
two hostile passes.

## Verdict

**VERDICT: PLAN-READY** (narrowed scope: PLAN-KILL Residual-1's code change; land
Residual-2 + Residual-3 + the doc-accuracy fix as one small `/engineer` PR, with the
documented option to drop Residual-2 for minimalism). One MINOR wording nit from Probe
A to fold if a further revision happens; not a blocker.
