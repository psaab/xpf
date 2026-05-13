# v8 Multi-Sample Fairness Runbook

Issue #1232 exists because a single iperf-e run can overstate or
understate fairness. Source-port randomness changes the RSS placement,
so the useful measurement is the run-to-run distribution of
`observed_cov`, `Cstruct`, and the contract gap
`observed_cov - Cstruct`, not one lucky sample.

Use the wrapper below for the canonical five-sample run:

```bash
python3 test/incus/fairness_multi_sample.py \
  --samples 5 \
  --out-dir /tmp/xpf-v8-multi-sample-$(date +%Y%m%d-%H%M%S) \
  --max-mean-gap 5% \
  --max-run-gap 5% \
  --per-run-timeout-sec 600 \
  -- \
  2001:559:8585:80::200 5205 12 120 "" http://127.0.0.1:8080/metrics
```

The command runs `test/incus/fairness-harness.sh` five times, stores
each sample's stdout, stderr, command, placement artifacts, and
`verdict.json`, then writes `summary.json` with:

- mean/sample-standard-deviation/min/max observed CoV
- mean/sample-standard-deviation/min/max `Cstruct`
- mean/sample-standard-deviation/min/max gap
- per-run fairness verdicts and failure reasons

`--samples` must be at least `2`; the canonical run is `5` samples.
The default thresholds are the Cstruct-aware fairness contract:
`--max-mean-gap 5%` and `--max-run-gap 5%`. Absolute observed-CoV
thresholds are disabled by default because high observed CoV is
expected under skewed RSS placement; the meaningful question is whether
observed CoV exceeds the structural ceiling. Operators can still add
`--max-mean-cov`, `--max-stdev-cov`, and `--max-run-cov` for a
deliberately balanced-RSS fixture, but those are opt-in diagnostics, not
the product fairness gate.

For strict exact-CoS lease experiments, keep the default Cstruct gap
thresholds and add explicit absolute-CoV observations to the report.
Those experiments intentionally allow a shaped queue to leave unarmed
surplus idle, so a useful result must show both lower absolute per-flow
spread and the aggregate-throughput cost paid to get it.

The wrapper reads stdout JSON objects that match the fairness-eval
verdict schema (`verdict`, `observed_cov`, `cstruct`, `gap`,
`failure_reasons`, `distribution_a_i`, `n_active`, `saturated`,
`a_i_sum_check_ok`, and `starved_flow_count`) and ignores all other
structured logs. Each sample must emit exactly one verdict object with
finite, non-negative `observed_cov` and `cstruct`, plus a finite `gap`
which may be negative when the measured result is better than the
structural ceiling. If `aggregate_mbps` is present, it is also
finite/non-negative validated.
`starved_flow_count` must be a non-negative integer. Every harness run
has a 600-second default timeout; on timeout the wrapper kills the entire
process group (including iperf3 and scraper descendants) before writing
the partial stdout/stderr and `command.json` with `timed_out: true`.

**Important**: each sample must exercise a fresh iperf3 measurement
with a new ephemeral source-port set, not a replay of a fixed snapshot.
The harness creates a fresh temp directory and reruns iperf3 for each
invocation, so invoking the wrapper N times yields N independent RSS
placement draws. Do not invoke `fairness_multi_sample.py` against a
pre-captured static snapshot — every run would produce identical
`observed_cov` and the stdev would be trivially 0.

**Threshold derivation**: `--max-run-gap 5%` matches the single-run
`fairness-eval` contract (`observed_cov <= Cstruct + 0.05`).
`--max-mean-gap 5%` prevents the aggregate verdict from passing a set of
borderline samples by averaging away a persistent positive gap. Absolute
CoV stability bounds are intentionally opt-in because RSS entropy can
move the structural ceiling across samples without indicating a
scheduler regression.

The wrapper exits:

- `0` when all samples PASS and the aggregate gap thresholds pass
- `1` when at least one fairness verdict or aggregate threshold fails
- `2` for harness timeout, parsing, validation, or environment errors

This is a measurement runbook, not the final empirical result. Close
#1232 only after running it on the loss userspace cluster with the
current userspace dataplane and recording the resulting `summary.json`.
