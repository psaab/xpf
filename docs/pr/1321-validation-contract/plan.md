# Issue #1321 Validation Contract

Status: implemented narrow slice on branch `codex/1321-validation-contract`.

## Goal

Advance issue #1321 without changing dataplane scheduling behavior. The
useful slice is a stable validation surface for:

- 100 elephant + 100 mouse artifacts under strict exact and
  surplus-sharing modes.
- work-conserving surplus borrow/give-back phase artifacts.
- explicit separation between surplus-sharing and equal-flow comparison.

## Design decisions

1. Reuse the mouse-latency matrix artifact format instead of adding a
   second 100E100M reducer. The matrix runner now accepts env-configured
   cells and gate parameters, so `/tmp/.../cell_N100_M100` and
   `/tmp/.../cell_N0_M100` are enough for the 100E100M gate.
2. Preserve p99.9 in probe and aggregate artifacts as `p999` /
   `p999_us`. Legacy #905-style runs keep the default p99 gate for
   compatibility. The canonical 100E100M runs set
   `MOUSE_LATENCY_GATE_PERCENTILE=p999_us`, and the reducer selects the
   representative rep by the same percentile it gates.
3. Validate surplus give-back from a reduced phase JSON artifact. The
   first live runner can be shell, Python, or an operator-curated
   reducer, but pass/fail semantics are centralized in
   `fairness_surplus_giveback_validate.py`.
4. Do not alter dataplane hot path or scheduler behavior in this lane.
   Issue #1321 is a validation contract until live artifacts prove a
   concrete implementation defect.

## 100E100M commands

Strict exact fixture:

```bash
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
MOUSE_LATENCY_CELLS=$'0 100\n100 100' \
MOUSE_LATENCY_GATE_ELEPHANTS=100 \
MOUSE_LATENCY_GATE_MICE=100 \
MOUSE_LATENCY_GATE_PERCENTILE=p999_us \
./test/incus/test-mouse-latency-matrix.sh /tmp/xpf-100e100m-exact
```

Surplus-sharing fixture:

```bash
./test/incus/apply-cos-config.sh --surplus-sharing loss:xpf-userspace-fw0
MOUSE_LATENCY_CELLS=$'0 100\n100 100' \
MOUSE_LATENCY_GATE_ELEPHANTS=100 \
MOUSE_LATENCY_GATE_MICE=100 \
MOUSE_LATENCY_GATE_PERCENTILE=p999_us \
./test/incus/test-mouse-latency-matrix.sh /tmp/xpf-100e100m-surplus
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
```

The 100E100M qualification gates p99.9. The reducer also supports p99
for legacy #905-style runs.

## Surplus Give-Back Artifact

Minimum artifact:

```json
{
  "root_cap_mbps": 25000,
  "borrower_guarantee_mbps": 10000,
  "peer_guarantee_mbps": 10000,
  "handback_window_sec": 3.2,
  "handback_evidence": {"source": "transition_observed", "observed": true},
  "phases": [
    {"name": "borrow_alone", "throughput_mbps": {"borrower": 18000, "peer": 0}},
    {"name": "peer_demand", "throughput_mbps": {"borrower": 16000, "peer": 7000}},
    {
      "name": "peer_steady",
      "throughput_mbps": {"borrower": 9000, "peer": 9800},
      "cos_admission_drops": {"peer": 0}
    },
    {"name": "peer_idle_reclaim", "throughput_mbps": {"borrower": 17000, "peer": 0}}
  ]
}
```

Validation:

```bash
./test/incus/fairness_surplus_giveback_validate.py \
  --input /tmp/xpf-surplus-giveback/phases.json \
  --out /tmp/xpf-surplus-giveback/verdict.json
```

The validator exits `0` for PASS, `1` for contract FAIL, and `2` for
malformed artifact or infrastructure misuse.

`handback_window_sec` must be auditable. A live runner may either attach
`handback_samples` time-series entries and let the validator compute the
first handback point, or attach `handback_evidence` showing the scalar
was measured from a real transition. The validator also checks that the
borrower actually borrowed above its guarantee, the peer-demand phase
actually had non-zero peer activity, and the borrower reclaimed close to
the borrow-alone baseline after the peer went idle. The peer-demand
threshold is deliberately a low liveness proxy; guarantee service is
enforced by `peer_steady` and the handback evidence.

## Focused Validation

```bash
python3 -m py_compile \
  test/incus/mouse_latency_probe.py \
  test/incus/mouse_latency_aggregate.py \
  test/incus/fairness_surplus_giveback_validate.py

(cd test/incus && python3 -m unittest \
  mouse_latency_probe_test.py \
  mouse_latency_aggregate_test.py \
  fairness_surplus_giveback_validate_test.py)
```
