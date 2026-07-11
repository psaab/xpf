# Claude SMR — HOSTILE plan review r2 — #5562 snapshot coherence

Reviewing `plan.md` r2 (post F1–F6 fold). This pass is **Claude-SMR-primary**: Codex is
infra-blocked (CLI 1.0.6 / ChatGPT account — 5 model retries, all rejected) and AGY
malfunctioned on all 3 attempts (off-task hallucination about a `--print-timeout` flag,
never read the plan — the known "companion CLI lost results" mode). With both companions
down, this pass deliberately takes the angle a hostile Codex would: **does closing the
flow-cache hole actually close the fail-open end-to-end, or does the packet fall through to
another consumer of `validation.config_generation` that Path D leaves stale?**

## Verdict: **PLAN-NEEDS-MINOR** (one new finding F7; folds into r3 → PLAN-READY)

Path D is still correct and remains the recommendation. But r2 undersold the reader
enumeration in one material way and made one **wrong** cleanup claim. Both fixed by F7.

## New finding

### F7 (MINOR, corrects reader enumeration + a wrong cleanup claim) — `classify_metadata` is a SECOND worker consumer of `validation.config_generation`, and it must stay on validation
r2 §2.7 / §11.3 claimed the worker reads `validation.config_generation` **only** for the
flow-cache stamp. That is **wrong**. `forwarding::classify_metadata` (forwarding/mod.rs
L30–47) also reads it:
```
if meta.config_generation != validation.config_generation {
    return PacketDisposition::ConfigGenerationMismatch;   // L37-38
}
```
Called on the main RX path (`poll_descriptor/mod.rs`) and the inject path
(`coordinator/inject.rs`). But this is a **different coherence axis**:
`meta.config_generation` is stamped by the **shim**, read from the `userspace_ctrl` BPF map
(userspace-xdp/src/lib.rs L115/L406 `USERSPACE_CTRL.get(0)` → `ctrl.config_generation`), NOT
from the worker's forwarding or validation ArcSwap. So `classify_metadata` compares
**shim-view (ctrl map) vs worker-view (validation)** — a shim↔worker skew gate — whereas the
flow-cache bug is **worker-validation vs worker-forwarding**. They are orthogonal.

Two consequences the plan MUST state:

1. **Path D must NOT move `classify_metadata` to `forwarding.config_generation`.** Its
   `meta.config_generation` comes from the shim's ctrl map, which the coordinator keeps in
   step with `validation`, not with the forwarding-embedded copy. Sourcing this gate from
   forwarding would compare two things that were never intended to match. Leave it on
   validation. (This is why Path D is *split-source*, not *move-everything*.)

2. **The §10 / §11.2 "optional cleanup: remove `config_generation` from the worker-visible
   `ValidationState`" is NOT viable and must be struck.** `classify_metadata` still needs
   `validation.config_generation`. r2's claim that the worker "no longer reads
   `validation.config_generation`" after Path D is false — it stops reading it *for the
   stamp*, but `classify_metadata` keeps reading it. Correct §10 and §11.2.

Neither consequence weakens Path D. In fact F7 confirms the fix is properly scoped: only the
flow-cache stamp/lookup migrate; classify_metadata is a fail-closed gate on a separate axis.

## Attacks that did NOT land (verified)

- **"Does the packet fall through to a still-permitted established session, making the
  flow-cache gate redundant?"** No. `classify_metadata` (the slow-path generation gate) is
  fail-CLOSED — a mismatch returns `ConfigGenerationMismatch`, which bumps an exception
  counter and records an exception (disposition.rs L315–329); the packet is not fast-path
  forwarded. So the flow-cache generation gate is a genuine enforcement surface, not a
  redundant cache in front of a permissive session layer. The #5562 fail-open is real
  end-to-end.
- **"Does classify_metadata itself have the same torn-read fail-open?"** No — on any skew it
  fails **closed** (drops/exceptions), so shim↔worker skew during a config window costs a few
  dropped packets (sender retransmits), never a stale permit. Not a fail-open vector; out of
  scope for #5562.
- **"Does Path D create an inconsistency between the two gates?"** No — they answer different
  questions and are both monotone; a packet that passes classify_metadata (shim==worker==N)
  but hits worker-forwarding N-1 is exactly the #5562 window, and Path D's forwarding-sourced
  stamp is what closes it. The two gates compose correctly.

## Required for r3 → PLAN-READY

Fold F7: (a) add `classify_metadata` to the §2.7 reader enumeration as the second consumer of
`validation.config_generation`, on the shim↔worker axis; (b) state Path D leaves it on
validation deliberately (§5 Path D + §7 invariants); (c) strike the "remove config_generation
from validation" cleanup from §10 and §11.2 — it is not available. No design change; Path D
stands. After F7 is folded and no blocking issue remains, this is **PLAN-READY**
(Claude-SMR-primary, Codex+AGY infra-block documented for /engineer-time re-attempt).
