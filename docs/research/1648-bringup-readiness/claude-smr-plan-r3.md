# Claude SMR hostile plan-review — r3

Reviewing plan v3. Both r2 companions (Codex + AGY) converged on the SAME
critical blocker — the trace-map retransmit overwrite. I independently verified
it against source before accepting, and judge the v3 fold complete.

## Verdict: PLAN-READY

## Independent verification of the r2 critical blocker (retransmit overwrite)

The Gate-R tcpdump (`plan.md:40-42`) shows SYN-1 (dropped) and the +1.007s
retransmit SYN-2 (answered) on the **same 5-tuple** (`10.0.61.102.57282 >
172.16.80.200.5201`). The trace key is a hash of ONLY (ingress_ifindex, protocol,
src_port, dst_port) (`lib.rs:999-1002`), so SYN-1 and SYN-2 collide on the key.
`record_trace` inserts with flag `0` = `BPF_ANY` (`lib.rs:1003
USERSPACE_TRACE.insert(&trace_key, &value, 0)`), i.e. upsert/overwrite. SYN-2
takes the success path and calls `record_trace(... USERSPACE_TRACE_STAGE_REDIRECT
...)` at `lib.rs:625-634` before the redirect at `:635`. Therefore a post-hoc
dump reads SYN-2's REDIRECT and SYN-1's drop stage is GONE. **The blocker is
real; a "dump after connect" Gate-B would have produced a false-negative on the
drop window — exactly the kind of measurement artifact that let H-0 look
plausible before Gate-R.** Both reviewers' fix (throwaway shim writes only
drop/error stages, early-return for RECEIVED/REDIRECT) cleanly prevents the
overwrite. v3 B-2 adopts it verbatim and marks it mandatory. Correct.

## v3 fold audit

1. **Retransmit overwrite (Codex r2-1 / AGY r2-3)** — folded: B-2 now mandates
   drop-stages-only `record_trace` in the throwaway shim. Correct.
2. **B-2 title / B-5 overclaim (Codex r2-2)** — folded: B-2 title and B-5 now say
   the trace map pins W-BIND/W-READY/W-HB/W-XSK ONLY; W-CTRL via
   timeline+`ctrl_disabled`; W-PASS-KERNEL via the up-front ingress-iface counter.
   Correct.
3. **Path 1.A all writers (Codex r2-3 / AGY r2-A,B)** — folded: §5 1.A lists the
   uniform set {primary `:596`, alias `:633`, watchdog `:1072/:1101`,
   watchdog-alias `:1122/:1145`} and marks the watchdog update mandatory (it would
   re-open W-XSK on rebind otherwise). Correct.
4. **Ingress-iface-miss counter up front (Codex r2-4)** — folded: B-4 now builds
   the eBPF counter at `lib.rs:366` into the throwaway shim from the start.
   Correct.
5. **Crash-blind deadlock (AGY r2-C)** — folded as a bonus correctness argument
   FOR Path 1.A, with the honest /engineer caveat that `Ready`'s heartbeat-fresh
   term could flap the BPF flag per poll and must be confirmed stable. Correct
   and appropriately cautious.

## No new holes

I checked whether the drop-stages-only trace filter could itself miss the data
SYN: the drop stages include all of BINDING_MISSING/BINDING_NOT_READY/
HEARTBEAT_MISSING/HEARTBEAT_STALE/REDIRECT_ERR, which cover every trace-recording
drop window (W-BIND/W-READY/W-HB/W-XSK). W-CTRL and W-PASS-KERNEL are
non-trace-recording and are covered by the timeline + dedicated counters. So the
six-window coverage is complete and consistent. The `seq`(ktime) field is
correctly demoted to a secondary discriminator (insufficient alone once
overwritten). No residual measurement-validity gap.

## Bottom line

Gate-B is now executable and can pin the dropped SYN to exactly one of the six
windows without the retransmit-overwrite false-negative. The honesty gate (B-6)
correctly mandates PLAN-KILL if the measurement refutes the readiness-gate
framing. Path 1.A is the favored fix on current source evidence (it eliminates
the W-XSK race AND the latent crash-blind blackhole, strictly tightens
fail-closed, reuses already-shipped status), with Path 1.C contingent on the
measured gap being poll-dominated and Path 3 viable if the fail-closed-path change
cost is judged to exceed removing one deploy RTO. PLAN-READY for Gate-B.
