# Claude SMR plan review — round 2

**Plan:** v1.2. **Verdict: PLAN-NEEDS-MINOR → converging.**

Self-correction: my r1 m1 said "workers=1 → queue_count=1 → all to queue 0."
Codex r1 correctly refuted that — `queue_count = queueCountFromBindings(status
.Bindings)` (the binding INVENTORY), NOT the worker count; Rust plans bindings
from the RX-queue inventory (`worker_id = queue_id % workers`). So the
queue-bound-stranding mechanism is real but is gated on the binding inventory,
not the worker count, and `workers=4` neither proves nor refutes A without
reading whether q0..q3 are each bound+ready+xsk-registered+`socket_queue_id`-
matched. v1.2 folds this: the binding/XSK inventory is now the PRIMARY
discriminator, degraded counters secondary, and v1.2 records that a queue-bound
stranding can die in the kernel XSK-delivery WITHOUT any `fallback_stats`
increment (so "no counter + rx=0" does not auto-imply B).

With those corrections the plan's diagnosis decision-tree is sound and
code-grounded. Remaining: AGY's independent read (re-dispatched after an
infra-timeout) + a Codex r2 confirm on v1.2. No architectural objection from me.
