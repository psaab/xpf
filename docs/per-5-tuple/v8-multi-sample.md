# v8 Multi-Sample Fairness Runbook

Issue #1232 exists because a single iperf-e run can overstate or
understate CoV stability. Source-port randomness changes the RSS
placement, so the useful measurement is the run-to-run distribution of
`observed_cov`, not one lucky sample.

Use the wrapper below for the canonical five-sample run:

```bash
python3 test/incus/fairness_multi_sample.py \
  --samples 5 \
  --out-dir /tmp/xpf-v8-multi-sample-$(date +%Y%m%d-%H%M%S) \
  --max-mean-cov 15% \
  --max-stdev-cov 3% \
  --max-run-cov 25% \
  --per-run-timeout-sec 600 \
  -- \
  2001:559:8585:80::200 5205 12 120 "" http://127.0.0.1:8080/metrics
```

The command runs `test/incus/fairness-harness.sh` five times, stores
each sample's stdout, stderr, command, placement artifacts, and
`verdict.json`, then writes `summary.json` with:

- mean observed CoV
- sample standard deviation of observed CoV
- min/max observed CoV
- per-run fairness verdicts and failure reasons

`--samples` must be at least `2`; the canonical run is `5` samples.
The default thresholds are CI-grade stability guards over repeated
iperf-e placement draws, not fairness constants. `--max-mean-cov 15%`
is the headline stability gate, `--max-stdev-cov 3%` rejects unstable
run-to-run RSS/placement variance, and `--max-run-cov 25%` prevents one
bad run from being hidden by the mean.

The wrapper reads stdout JSON objects that match the fairness-eval
verdict schema (`verdict`, `observed_cov`, `cstruct`, `gap`,
`failure_reasons`, `distribution_a_i`, `n_active`, `saturated`,
`a_i_sum_check_ok`, and `starved_flow_count`) and ignores all other
structured logs. Each sample must emit exactly one verdict object with
finite, non-negative `observed_cov`, `cstruct`, and `gap`; if
`aggregate_mbps` is present, it is also finite/non-negative validated.
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

**Threshold derivation**: `--max-mean-cov 15%` is a conservative
stability gate for production-shaped v8 flow sets whose observed CoV is
expected to sit in the low-to-mid teens when the dataplane is healthy.
`--max-run-cov 25%` bounds one unfavorable RSS placement draw from being
hidden by the mean. `--max-stdev-cov 3%` allows for about ±0.03 of
run-to-run noise from ephemeral-port RSS entropy; a stdev above 0.03
indicates structural instability rather than sampling noise. These
thresholds should be updated if the dataplane or NIC configuration
changes materially.

The wrapper exits:

- `0` when all samples PASS and the mean/stdev/max CoV thresholds pass
- `1` when at least one fairness verdict or aggregate threshold fails
- `2` for harness timeout, parsing, validation, or environment errors

This is a measurement runbook, not the final empirical result. Close
#1232 only after running it on the loss userspace cluster with the
current userspace dataplane and recording the resulting `summary.json`.
