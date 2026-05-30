# AGY adversarial plan-review r2 — #1692 (job adversarial-review-mpsiltqk-jhkdi6)

Verdict: PLAN-NEEDS-MAJOR.

## (1) Residual aliasing — backlog_i ~= 0 does NOT separate (0) from (L1) under TCP closed-loop
A share-capped (L1) worker can show backlog_i ~= 0 in steady state. Under
sustained TCP, the sender's congestion control paces transmission DOWN to
the L1-enforced bottleneck rate; once arrival rate == service rate, queue
occupancy (queue.hot.queued_bytes) drops to ~0 despite active L1
throttling. v2 Decision Rule 1 (backlog~=0 -> DEMAND-BOUND -> PLAN-KILL)
then fires a FALSE-POSITIVE kill on an active L1 limitation. The v1/v2
"park-without-pop keeps the queue full" argument only holds OPEN-LOOP
(arrivals > service); TCP makes arrivals converge to service.

## (2) share_integral_i undercount defect
acquire_v8 (and thus maybe_rotate_epoch_v8, mod.rs:1176) is called on
token-bucket TOP-UP, not every 200us epoch. A worker that banks tokens
skips top-ups -> skips rotations -> the piggybacked
`share_integral_i += my_share` (one epoch's worth) misses the entitlement
of every skipped epoch. Meanwhile one delayed acquire grants a MULTI-epoch
cap (cap = rate x elapsed, elapsed = wall-clock lag bounded by K=8 epochs,
rotate_epoch_v8.rs:262-295). Result: granted_i > share_integral_i, which
breaks v2's `granted_i ~= share_integral_i` L1 fingerprint.

## (3) RSS multinomial drift under low parallelism
At -P 12 over 6 queues, flow-to-worker mapping can drift mid-window;
active_flow_buckets[i] steps, so my_share steps discontinuously and the
windowed share_integral has high variance, polluting the L1-vs-L3 ratio.
