# Claude SMR plan-review — #1780 round 1 (v1 @ 4952048c4)

**Verdict: PLAN-NEEDS-MAJOR** — the plan proposes fixes (Path A/B) before the
root cause is actually pinned, and I've now had TWO refuted hypotheses, so the
third (compounding-slowness) deserves the same skepticism, not a fix design.

## The unpinned crux
The plan claims "compounding slowness (neg-cache 3s + resolver rate-limit + TCP
SYN backoff)" — but it does NOT explain the load-bearing fact: **why does
neighbor resolution take seconds instead of one ARP RTT (~ms)?** The first
buffered SYN probes `.200` immediately (poll_descriptor MissingNeighbor arm);
if `.200` ARP-replies in 1 RTT, the entry is REACHABLE within ms and the
buffered SYN dispatches — no multi-second hang. So *something* makes resolution
take seconds, and the plan hand-waves it as "rate-limit + backoff" without
proof.

Most likely the real delay is the **kernel's ARP retransmit cycle to an
initially-unresponsive `.200`** (INCOMPLETE → ucast/mcast solicit retries over
`retrans_time` → FAILED → re-trigger), i.e. `.200`-side / kernel behavior, NOT
the userspace resolver's rate-limit. If so, **Path B (first-probe-bypass of the
resolver rate-limit) fixes the wrong thing** — shaving 1s off a resolver GET
that isn't the bottleneck. That's a real risk of churning the resolver hot-ish
path for no gain.

## Track record demands humility here
- Hypothesis 1 (warmer-off directly hangs): REFUTED by the 23-min test.
- Hypothesis 2 (resolver revokes-without-probing): REFUTED by `decide_action`.
- Hypothesis 3 (compounding-slowness + Path B fixes it): UNVERIFIED, and its
  premise (resolver rate-limit is the bottleneck) is unproven.

Three swings; the discipline (`feedback_runnable_repro_before_measurement_claim`)
says: **do not design a fix on the 3rd hypothesis without the capture.**

## What the plan SHOULD be (revision direction)
Re-scope v1 from "fix via A/B" to **"diagnose-first"**:
1. **Path A (warmer reliability) is the one defensible fix to commit to now** —
   it's prevention (keep `.200` REACHABLE so the cold path never triggers), it's
   independently correct (a warmer stalled 17.5h with the daemon up IS a bug
   regardless of the hang), and it's verifiable (read the `queue_warm_pass`
   driver + its gate). Keep Path A.
2. **Defer Path B** until the capture shows the resolver is the bottleneck
   (`get_attempts` climbing, resolution wall-time dominated by resolver
   rate-limit, NOT kernel ARP retransmit). Add the instrumentation needed to
   tell these apart: a resolver GET→resolve wall-time histogram + a
   `neighbor_warm_last_pass_age` gauge.
3. The capture (running + operator overnight) is a HARD gate on Path B's design.

## Recommendation
PLAN-NEEDS-MAJOR: split into (a) Path A warmer-reliability + observability
(commit-worthy now, root-cause-independent), and (b) a diagnostic step
(instrument resolution wall-time) that gates any resolver-path change. Do NOT
ship Path B's first-probe-bypass until the capture proves the resolver — not
the kernel ARP cycle to a cold `.200` — is the multi-second delay.
