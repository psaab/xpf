# Codex hostile plan-review — #1649 r1

Task: codex exec read-only, RSS/AF_XDP/kernel-networking expert framing.

## Findings (verbatim)

1. §5 is airtight only against the **reactive exact-5-tuple controller**, not
   against all initial-placement mechanisms. Plan says "SYN arrives. Hardware
   RSS ... picks the RX queue" and "there is no ntuple rule for an unseen
   5-tuple yet" (plan.md:170), then concludes any correction "moves the flow"
   (plan.md:176). That kills #1203-style reactive steering. But it overreaches
   at "No viable per-flow non-re-steer mechanism exists" (plan.md:205).

2. Concrete counterexample: **pre-installed source-port-residue ntuple rules**.
   The plan itself cites "3.8% with deterministic per-port-mod assignment"
   (plan.md:160). That is a non-reactive classifier over future source-port
   space, installed before the SYN, and therefore not a re-steer. §6 only lists
   "destination-port or subnet" pre-partitioning (plan.md:198) and then claims
   same-dst-port iperf "cannot pre-partition without knowing src-port"
   (plan.md:202). That is false as written: masked source-port classes
   pre-partition the future src-port space without knowing the exact ephemeral
   port in advance.

3. The N<=M angle is not pre-empted by #1203. Plan admits #1649's case is
   "N=6 flows, M=6 workers" and "distinct from #1203's P=12" (plan.md:156).
   #1203 pre-empts reactive closed-loop placement for N>M. It does not kill a
   static initial classifier that tries to place P=6 as one flow per queue.
   The plan should narrow the kill to arbitrary production accepts with random
   source ports, not controlled source-port sequences.

4. Empirical claims mostly plausible, not all kill-grade. 1024-rule cap credible
   (plan.md:97). The 1.1ms/rule estimate is plausible but weak because it
   subtracts an incus-exec fork baseline from a different command path
   (plan.md:109); it should not carry the kill. RX-queue-to-worker determinism
   strong (plan.md:122); wording should be "queue-bound deterministic binding,"
   not universal "worker N."

5. Salvage is not hand-pinned exact 5-tuples (that is a #1203 retread). The
   salvage worth analyzing is narrower: an explicit opt-in **static
   source-port-residue / service-specific RSS-context initial-placement mode**
   for controlled long-lived workloads or test harnesses. It may fail for random
   ephemeral ports and may hurt aggregate, but it is a real non-re-steer
   mechanism, and the plan's own Phase-0 evidence says it can work.

External source check: Linux docs confirm n-tuple filters/RSS contexts can steer
matched traffic before queue delivery, TC can select RX queues in hardware,
AF_XDP sockets are queue-bound, and RFS/aRFS are reactive rather than
first-packet placement mechanisms.

## VERDICT: PLAN-NEEDS-WORK (static source-port-residue ntuple/RSS-context pre-partition)
