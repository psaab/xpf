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

The wrapper reads stdout JSON objects with a top-level `verdict` key and
ignores non-verdict structured logs. Each sample must emit exactly one
verdict object with finite, non-negative numeric fields. Every harness
run has a 600-second default timeout; a timeout writes the partial
stdout/stderr and `command.json` with `timed_out: true` before the
wrapper exits `2`.

The wrapper exits:

- `0` when all samples PASS and the mean/stdev/max CoV thresholds pass
- `1` when at least one fairness verdict or aggregate threshold fails
- `2` for harness timeout, parsing, validation, or environment errors

This is a measurement runbook, not the final empirical result. Close
#1232 only after running it on the loss userspace cluster with the
current userspace dataplane and recording the resulting `summary.json`.
