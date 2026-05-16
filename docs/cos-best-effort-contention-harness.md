# CoS Best-Effort Contention Harness

`test/incus/cos-be-contention-harness.sh` validates the 5200/5211 CoS port-grid
edge cases where an exact class must hold its exact-alone throughput while a
best-effort or uncapped-root contender is present.

The default run targets the isolated loss userspace cluster, applies the
symmetric CoS fixture, and runs IPv4 forward traffic from
`loss:cluster-userspace-host` to `172.16.80.200`.

## Cells

The smoke matrix is intentionally small:

| Cell | Exact queue | Exact port | Contender queue | Contender port |
|---|---:|---:|---:|---:|
| `exact5202-vs-5200` | 2 | 5202 | 0 | 5200 |
| `exact5210-vs-5200` | 10 | 5210 | 0 | 5200 |
| `exact5202-vs-5211` | 2 | 5202 | 11 | 5211 |
| `exact5210-vs-5211` | 10 | 5210 | 11 | 5211 |

Each cell runs:

1. exact-alone baseline
2. exact plus contender
3. offline validation of iperf summaries and queue DrainShape deltas

## Usage

```bash
./test/incus/cos-be-contention-harness.sh
```

Useful overrides:

```bash
DURATION=20 EXACT_PARALLEL=6 CONTENDER_PARALLEL=6 \
ARTIFACT_ROOT=/tmp/cos-be-contention \
./test/incus/cos-be-contention-harness.sh
```

Run one cell:

```bash
CELL_FILTER=exact5202-vs-5200 ./test/incus/cos-be-contention-harness.sh
```

Skip config apply when the symmetric fixture is already live:

```bash
APPLY_CONFIG=0 ./test/incus/cos-be-contention-harness.sh
```

The default `DURATION=8` and `-P4` settings are short enough for smoke. Increase
duration and parallelism for qualification.

## Gates

The validator fails closed when:

- any iperf run exits non-zero
- status snapshots are missing or their capture commands exit non-zero
- an expected queue has no `drain_sent_bytes` delta
- any queue has a negative DrainShape counter delta
- an expected queue's `forwarding_class` does not match the manifest
- any unexpected queue drains more than `WRONG_QUEUE_SENT_BYTES_TOLERANCE`
- the contender iperf throughput is below `MIN_CONTENDER_BPS`, because a
  no-pressure contender cannot prove exact-queue isolation
- exact+contender throughput drops below exact-alone throughput by more than
  `MAX_EXACT_DROP_RATIO`

Defaults:

```bash
MAX_EXACT_DROP_RATIO=0.15
WRONG_QUEUE_SENT_BYTES_TOLERANCE=0
MIN_EXPECTED_SENT_BYTES=1
MIN_CONTENDER_BPS=100000000
COS_INTERFACE_NAME=reth0.80
```

Set `COS_IFINDEX` to pin validation to a specific CoS interface if interface
names are ambiguous.

## Artifacts

The harness writes an artifact root such as `/tmp/cos-be-contention.xxxxxx`.
Important files:

- `manifest.json`: cell definitions and CoS interface filter
- `summary.json`: full verdict, thresholds, throughput, and queue deltas
- `summary.tsv`: compact per-cell verdict and throughput table
- `drain-shape.tsv`: per-cell, per-phase queue `sent_bytes`,
  `park_root`, and `park_queue` deltas
- `<cell>/baseline/*`: exact-alone iperf and status snapshots
- `<cell>/contended/*`: exact+contender iperf and status snapshots

Each phase contains:

- `status-before.json`, `status-during.json`, `status-after.json`
- `exact-iperf.json`, `exact-iperf.rc`, `exact-iperf.stderr`
- `contender-iperf.json`, `contender-iperf.rc`, `contender-iperf.stderr`
  for contended phases

The offline validator can be rerun against saved artifacts:

```bash
python3 test/incus/cos_be_contention_validate.py /tmp/cos-be-contention.xxxxxx
```
