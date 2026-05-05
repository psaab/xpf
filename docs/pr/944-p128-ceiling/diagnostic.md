---
status: CLOSED — NEEDS-NO-FIX
issue: https://github.com/psaab/xpf/issues/944
phase: Diagnostic — verify post-#917 + V_min fixes (#940-#943)
---

## Summary

The P=128 ~17 Gb/s ceiling reported in #944 **does not reproduce**
on current master (commit `4d3c0964`, post-#917 MQFQ Phase 4 +
V_min correctness fixes #940/#941/#942/#943, plus #1190 #867
ACK-evasion). P=128 sustained throughput is now **23.6/23.7
Gb/s**, on par with P=12 (23.5 Gb/s) and at/above the **22 Gb/s
gate**. Per #944 acceptance, this closes as **NEEDS-NO-FIX —
already addressed by upstream landing**.

## Reproduction attempt

Test environment:
- Cluster: `loss:xpf-userspace-fw0/fw1` (userspace-dp, `loss-userspace-cluster.env`)
- Source: `loss:cluster-userspace-host` (10.0.61.102 → 172.16.80.200)
- Deployed binary: built from worktree at master HEAD `4d3c0964`
- Date: 2026-05-04

Command (best-effort port 5201, P=128, 15 s push):
```
iperf3 -c 172.16.80.200 -P 128 -t 15 -p 5201
```

Results (two consecutive runs on best-effort port 5201, plus one
run on the iperf-c shaped class port 5203):

| Run | Port (class) | Duration | Bytes | Throughput | Retrans | Direction |
|-----|------|---------:|------:|-----------:|--------:|-----------|
| 1   | 5201 (best-effort) | 15.02 s  | 41.3 GBytes | **23.6 Gb/s** | 22 564 | push |
| 2   | 5201 (best-effort) | 15.01 s  | 41.3 GBytes | **23.7 Gb/s** | 19 842 | push |
| 3   | 5203 (iperf-c, 25 Gb/s shape) | 15.01 s | 41.3 GBytes | **23.6 Gb/s** | 23 430 | push |

P=12 reference on the same binary, same target:

| Cell | Duration | Bytes | Throughput | Retrans | Direction |
|------|---------:|------:|-----------:|--------:|-----------|
| P=12 push    | 15.00 s | 41.0 GBytes | 23.5 Gb/s |  950 | push |
| P=12 reverse | 15.00 s | 40.0 GBytes | 22.9 Gb/s |    6 | `-R` reverse |

## Verdict against #944 acceptance criteria

- [x] Attempt reproduction of the P=128 ~17 Gb/s observation
      on the loss cluster (verify it's still a thing post-#917).
      **Outcome: NOT reproducible.** P=128 = 23.6/23.7 Gb/s, no
      measurable delta from P=12. The 5 hypotheses listed in
      the issue (per-worker MQFQ scaling cost, cross-bucket
      vtime contention, TX-completion saturation, flow cache
      thrashing, admission overhead) collectively no longer
      bottleneck below the 22 Gb/s gate.

- [x] Diagnostic doc (this file).

- [x] Fix proposal: close NEEDS-NO-FIX. The ceiling has been
      addressed by the prior PR landing chain (#917 MQFQ
      Phase 4 + V_min correctness #940/#941/#942/#943 +
      whatever else accreted between the original #944
      observation and master HEAD).

## Adjacent observation (separate issue, not this one)

The P=128 push direction shows ~20 k retransmits per 15 s run
(~0.07 % retrans rate at 23.7 Gb/s line rate ≈ 30 M packets).
P=12 push has only 950 retrans on the same path. P=12 reverse
has 6 retrans.

This is **not** the original #944 bottleneck. It looks like a
high-fan-in TX-side queueing artifact — possibly cwnd-collapse
under contention at 128 concurrent flows when the aggregate
hits the 23.6 Gb/s line ceiling. Worth filing as a separate
issue if the retrans count matters operationally; not a #944
follow-up.

## References

- Original #944 observation pointed at `tx.rs` line numbers
  that have since been refactored. Current locations:
  - MQFQ vtime / `cos_queue_min_finish_bucket`:
    `userspace-dp/src/afxdp/cos/queue_service/mod.rs`
  - Admission / flow share limit:
    `userspace-dp/src/afxdp/cos/admission.rs`
- Post-#917 baseline: `docs/pr/917-mqfq-phase4/findings-post-917.md`
- V_min correctness fix chain: #940, #941, #942, #943
- #905 same-class harness measurement context:
  `docs/pr/929-same-class-harness/findings.md`
