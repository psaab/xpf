# #1530 DPDK Final Validation — Summary

**Commit (Phase 3 source removal):** `(TBD — Phase B G0)`
**Cluster env:** `test/incus/loss-userspace-cluster.env`
**Nodes:** `loss:xpf-userspace-fw0`, `loss:xpf-userspace-fw1`
**LAN host:** `loss:cluster-userspace-host`
**WAN targets:** `172.16.80.200` / `2001:559:8585:80::200`
**Generated:** Phase A draft — overwritten by `scripts/build-summary.sh`
during Phase B execution.

## Gate results

| Gate | Description                                                | Result | Log |
|------|------------------------------------------------------------|--------|-----|
| G0   | Lock to Phase 3 source-removal SHA                         | TBD    | `commit.txt` |
| G1   | Clean grep — no production DPDK references                 | TBD    | `grep-dpdk-violations.log` |
| G2.a | `make build`                                               | TBD    | `make-build.log` |
| G2.b | `make build-ctl`                                           | TBD    | `make-build-ctl.log` |
| G2.c | `make build-userspace-dp`                                  | TBD    | `make-build-userspace-dp.log` |
| G2.d | `make test`                                                | TBD    | `make-test.log` |
| G3   | `make build-dpdk*` targets gone                            | TBD    | `make-n-build-dpdk.log` |
| G4   | Daemon rejects `set system dataplane-type dpdk`            | TBD    | `cli-reject-dpdk.log` |
| G5.a | CoS-off IPv4 push + reverse                                | TBD    | `smoke-v4-cosoff-{push,reverse}.log` |
| G5.b | CoS-off IPv6 push + reverse                                | TBD    | `smoke-v6-cosoff-{push,reverse}.log` |
| G5.c | CoS-on class sweep (v4 + v6, push + reverse)               | TBD    | `smoke-v{4,6}-coson-<class>-{push,reverse}.log` |
| G5.d | Screen / flood baseline (LAND + SYN-flood + ICMP-flood)    | TBD    | `smoke-screen-*.log` |
| G5.e | `make test-failover`                                       | TBD    | `make-test-failover.log` |

## Binary hashes — build host

```
(pending G2)
```

## Binary hashes — deployed (loss userspace cluster)

```
(pending G5 pre-flight)
```

## Config files used

- `docs/ha-cluster-userspace.conf` (deployed by `cluster-setup.sh deploy`)
- CoS re-applied via `test/incus/apply-cos-config.sh` per node
  (deploy wipes CoS)

## G1 violations (head)

```
(pending G1)
```

## G3 — make -n exit codes

```
(pending G3)
```

## G4 — CLI rejection capture

```
(pending G4)
```

## G5 — SUM lines from each smoke run

(pending G5.a — G5.c)

## G5.e — failover summary (tail)

```
(pending G5.e)
```

## References

- Acceptance criteria: `gh issue view 1530`
- Umbrella: #1525
- Phase 3 source removal: #1528
- Sibling: #1477 (eBPF final validation)
- Runbook: `docs/pr/1530-dpdk-final-validation/runbook.md`
- Artifact ledger: `docs/pr/1530-dpdk-final-validation/artifacts.md`
