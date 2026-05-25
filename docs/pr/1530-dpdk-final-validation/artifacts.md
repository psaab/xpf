# #1530 DPDK Final Validation — Artifact summary

Filled by Phase B execution. Phase A leaves the schema and a stub
table; each row gets PASS/FAIL + log filename after the matching
gate runs.

## Commit

- Phase 3 merge SHA: `TBD (Phase B G0)`
- Date: `TBD`
- Cluster env: `test/incus/loss-userspace-cluster.env`
- Nodes: `loss:xpf-userspace-fw0`, `loss:xpf-userspace-fw1`
- LAN host: `loss:cluster-userspace-host`

## Binary hashes (build host)

- `xpfd`: `TBD`
- `cli`: `TBD`
- `userspace-dp/target/release/xpf-userspace-dp`: `TBD`

## Binary hashes (deployed)

- `loss:xpf-userspace-fw0:/usr/local/sbin/xpfd`: `TBD`
- `loss:xpf-userspace-fw0:/usr/local/sbin/xpf-userspace-dp`: `TBD`
- `loss:xpf-userspace-fw1:/usr/local/sbin/xpfd`: `TBD`
- `loss:xpf-userspace-fw1:/usr/local/sbin/xpf-userspace-dp`: `TBD`

## Config files used

- `docs/ha-cluster-userspace.conf` (deployed by
  `cluster-setup.sh deploy`)
- CoS re-applied via `test/incus/apply-cos-config.sh` per node
  (deploy wipes CoS)

## Gate results

| Gate | Description                                            | Result | Log file |
|------|--------------------------------------------------------|--------|----------|
| G0   | Lock to source-removal SHA                             | TBD    | `artifacts/commit.txt`, `artifacts/commit-show.txt` |
| G1   | Clean grep — no production DPDK references             | TBD    | `artifacts/grep-dpdk-violations.log` |
| G2   | Clean build (build + build-ctl + build-userspace-dp + test) | TBD    | `artifacts/make-build.log`, `artifacts/make-build-ctl.log`, `artifacts/make-build-userspace-dp.log`, `artifacts/make-test.log` |
| G3   | `make build-dpdk*` targets gone                        | TBD    | `artifacts/make-n-build-dpdk.log`, `artifacts/make-n-build-dpdk-exit.txt` |
| G4   | Commit rejects `set system dataplane-type dpdk`        | TBD    | `artifacts/cli-reject-dpdk.log` |
| G5.a | CoS-off IPv4 push + reverse                            | TBD    | `artifacts/smoke-v4-cosoff-{push,reverse}.log` |
| G5.b | CoS-off IPv6 push + reverse                            | TBD    | `artifacts/smoke-v6-cosoff-{push,reverse}.log` |
| G5.c | CoS-on class sweep (v4 + v6, push + reverse)           | TBD    | `artifacts/smoke-v{4,6}-coson-<class>-{push,reverse}.log` |
| G5.d | Screen / flood baseline (LAND, SYN-flood, ICMP-flood)  | TBD    | `artifacts/smoke-screen-*.log` |
| G5.e | `make test-failover`                                   | TBD    | `artifacts/make-test-failover.log` |

## Throughput numbers

Filled per smoke run:

| Test                          | Sender SUM | Retransmits | Notes |
|-------------------------------|------------|-------------|-------|
| v4 push CoS-off               | TBD        | TBD         |       |
| v4 reverse CoS-off            | TBD        | TBD         |       |
| v6 push CoS-off               | TBD        | TBD         |       |
| v6 reverse CoS-off            | TBD        | TBD         |       |
| v4 push CoS-on <class>        | TBD        | TBD         |       |
| ...                           | ...        | ...         |       |
| failover (min interval)       | TBD        | n/a         |       |
| failover (zero intervals)     | 0 expected | n/a         |       |

## Notes / blockers encountered

(Phase B fills.)
