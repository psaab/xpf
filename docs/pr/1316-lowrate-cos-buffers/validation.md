# PR #1316 validation: low-rate exact CoS fixture buffers

## Scope

PR #1316 pins deeper explicit buffers on the canonical iperf CoS fixtures:

- `scheduler-be buffer-size 500k` for q0 / 100 Mbps
- `scheduler-iperf-a buffer-size 4m` for q4 / 1 Gbps

The goal is to keep the reverse `-P 12` fairness qualification from
collapsing into persistent tail-drop at the two lowest rates. This is a
validation-fixture tradeoff: the explicit `buffer-size` values raise the
implicit default cap from roughly 10 ms of rate-derived buffering to about
40 ms for q0 and 32 ms for q4. #717 still contributes the 5 ms delay clamp
inside the implicit cap formula, but the default base (`rate/100`, with a
96 KB floor) is preserved by `delay_cap.max(base)`.

## Focused q0/q4 rerun

Artifact root: `/tmp/xpf-1312-buffer-20260515-122740`

Committed raw summaries copied from that run:
`evidence/focused-summary.tsv`,
`evidence/focused-dataplane-summary.tsv`, and
`evidence/focused-equal-flow-summary.tsv`.

| Queue | Port | Rate | Verdict | Retransmits by run | Notes |
|-------|------|------|---------|--------------------|-------|
| q0 | 5207 | 100 Mbps | PASS | 660, 619, 670 | admission drops fell from the earlier ~222k/run shape to ~1.9k aggregate |
| q4 | 5201 | 1 Gbps | PASS | 45, 581, 41 | admission drops fell from the earlier ~104k/run shape to ~527 aggregate |

Equal-flow enforcement had already been disabled in the prior diagnostic
rerun, so these drops were not caused by the equal-flow suppressor.

## Full seven-class sweep

Artifact root: `/tmp/xpf-1312-buffer-full-20260515-123820`

Committed raw summaries copied from that run:
`evidence/full-summary.tsv`,
`evidence/full-dataplane-summary.tsv`, and
`evidence/full-equal-flow-summary.tsv`.

| Queue | Port | Rate | Verdict | Avg Mbps | Utilization | Mean CoV | Max CoV | Retransmits by run | Dataplane drop notes |
|-------|------|------|---------|----------|-------------|----------|---------|--------------------|----------------------|
| q0 | 5207 | 100 Mbps | PASS | 82.40 | 82.4% | 0.0226 | 0.0678 | 666, 662, 688 | 2010 CoS admission drops; 0 residual TX-path drops |
| q4 | 5201 | 1 Gbps | PASS | 839.68 | 84.0% | 0.0010 | 0.0011 | 38, 15, 26 | 12 CoS admission drops; 40 redirect inbox drops |
| q5 | 5202 | 10 Gbps | PASS | 8405.88 | 84.1% | 0.0171 | - | 0, 0, 0 | 0 CoS admission / TX-path drops |
| q1 | 5204 | 13 Gbps | PASS | 10824.65 | 83.3% | 0.0197 | - | 0, 0, 0 | 0 CoS admission / TX-path drops |
| q2 | 5205 | 16 Gbps | PASS | 12808.41 | 80.1% | 0.0615 | - | 0, 0, 0 | 0 CoS admission / TX-path drops |
| q3 | 5206 | 19 Gbps | PASS | 14518.60 | 76.4% | 0.1133 | - | 38, 0, 0 | 0 dataplane drops |
| q6 | 5203 | 25 Gbps | PASS | 17396.98 | 69.6% | 0.1361 | - | 1113, 0, 0 | 0 dataplane drops |

All seven canonical classes passed after q0/q4 were buffered. The raw TSVs
are checked in so reviewers can audit the Markdown table without access to the
original `/tmp` directories. The high-rate classes still need to be included in
future regressions because low-rate classes can produce deceptively low CoV
while higher-rate classes expose RSS/bin-packing and CPU-limit effects.

The q0/q4 buffers are deliberately not a latency-default recommendation. They
buy retransmit stability for this reverse `-P 12` validation fixture by
allowing full-queue residence well above the implicit default cap. A production
low-latency class should size `buffer-size` from the service latency SLO and
must not inherit these fixture values without a queue-residence review.
