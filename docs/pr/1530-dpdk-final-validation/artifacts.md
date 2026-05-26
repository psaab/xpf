# #1530 DPDK Final Validation — Artifact summary

Phase B executed 2026-05-26 against the merged Phase 3 commit. G0-G4
PASS, G5 SMOKE-FAILED due to fw0 helper crash. See
`gh issue view 1530` for the full SMOKE-FAILED comment and bisect
recommendation.

## Commit

- Phase 3 merge SHA: `936b076d` (#1528 PR #1560, merged 2026-05-26T10:11Z)
- Worktree HEAD at Phase B execution: `d1d11908`
- Cluster env: `test/incus/loss-userspace-cluster.env`
- Nodes: `loss:xpf-userspace-fw0`, `loss:xpf-userspace-fw1`
- LAN host: `loss:cluster-userspace-host`

## Binary hashes (build host, this worktree)

- `xpfd`: `7334cf31f03b1319f232c7ed712337b971fb6a3a58c8fa050a02516edeb904b2`
- `cli`: `f587114af919f02a65d50788fb1501abd8fb357608081b32d9958f348d2b5431`
- `userspace-dp/target/release/xpf-userspace-dp`: `975f6fe3e740fd24d79c7ff195ba1e7f78ebd8ae6f94ce6dfec604836a17a448`

## Binary hashes (deployed)

cluster-setup.sh's deploy rebuilds with a slightly different version
string, producing a different `xpfd` hash than the local build copy.
The Rust userspace-dp helper hash matches exactly.

- `loss:xpf-userspace-fw0:/usr/local/sbin/xpfd`: `f6db3a2f21ed9039f0f9cdc9935b6283c10e6e0f1dbe4b9eff8682a24e79814d`
- `loss:xpf-userspace-fw0:/usr/local/sbin/xpf-userspace-dp`: `975f6fe3e740fd24d79c7ff195ba1e7f78ebd8ae6f94ce6dfec604836a17a448`
- `loss:xpf-userspace-fw1:/usr/local/sbin/xpfd`: `f6db3a2f21ed9039f0f9cdc9935b6283c10e6e0f1dbe4b9eff8682a24e79814d`
- `loss:xpf-userspace-fw1:/usr/local/sbin/xpf-userspace-dp`: `975f6fe3e740fd24d79c7ff195ba1e7f78ebd8ae6f94ce6dfec604836a17a448`

## Config files used

- `docs/ha-cluster-userspace.conf` (deployed by
  `cluster-setup.sh deploy`)
- CoS re-applied via `test/incus/apply-cos-config.sh` per node
  (deploy wipes CoS)

## Gate results

| Gate | Description                                            | Result   | Log file |
|------|--------------------------------------------------------|----------|----------|
| G0   | Lock to source-removal SHA                             | **PASS** | `artifacts/commit.txt`, `artifacts/commit-show.txt` |
| G1   | Clean grep — no production DPDK references             | **PASS** | `artifacts/grep-dpdk-violations.log` (empty) |
| G2   | Clean build (build + build-ctl + build-userspace-dp + test) | **PASS** | `artifacts/make-build*.log`, `artifacts/make-test.log` |
| G3   | `make build-dpdk*` targets gone                        | **PASS** | `artifacts/make-n-build-dpdk.log`, `artifacts/make-n-build-dpdk-exit.txt` |
| G4   | Commit rejects `set system dataplane-type dpdk`        | **PASS** | `artifacts/cli-reject-dpdk.log` |
| G5.a | CoS-off IPv4 push + reverse                            | DEGRADED | `artifacts/smoke-v4-cosoff-{push,reverse}.log` |
| G5.b | CoS-off IPv6 push + reverse                            | DEGRADED | `artifacts/smoke-v6-cosoff-{push,reverse}.log` |
| G5.c | CoS-on class sweep (v4 + v6, push + reverse)           | PARTIAL  | `artifacts/smoke-v{4,6}-coson-<class>-{push,reverse}.log` |
| G5.d | Screen / flood baseline (LAND, SYN-flood, ICMP-flood)  | NOT RUN  | (cluster degraded) |
| G5.e | `make test-failover`                                   | NOT RUN  | (cluster degraded) |
| **G5 overall** | HA smoke matrix on exact commit               | **FAIL** | `artifacts/fw0-helper-segfaults.log` |

## Throughput numbers (fw1-only path; fw0 helper crash)

| Test | Sender SUM | Retransmits | Notes |
|------|------------|-------------|-------|
| v4 push CoS-off (port 5200, -P 12) | 9.22 Gbps | 3334 | DEGRADED |
| v4 reverse CoS-off                 | 22.9 Gbps | 865 | mostly OK |
| v6 push CoS-off                    | 10.2 Gbps | 2645 | DEGRADED |
| v6 reverse CoS-off                 | 22.7 Gbps | 0 | OK |
| v4 push CoS-on iperf-100m (5201)   | 83 Mbps | 0 | shaped correctly |
| v4 push CoS-on iperf-1g (5202)     | 848 Mbps | 0 | shaped correctly |
| v4 push CoS-on iperf-3g (5203)     | 2.64 Gbps | 0 | shaped correctly |
| v4 push CoS-on iperf-6g (5204)     | 5.48 Gbps | 0 | shaped correctly |
| v4 push CoS-on iperf-9g (5205)     | 8.16 Gbps | 0 | shaped correctly |
| v4 push CoS-on iperf-12g (5206)    | 10.6 Gbps | 0 | shaped correctly |
| v6 push CoS-on iperf-100m          | 81.8 Mbps | 0 | shaped correctly |
| v6 push CoS-on iperf-1g            | 834 Mbps | 0 | shaped correctly |
| v6 push CoS-on iperf-3g            | 2.68 Gbps | 0 | shaped correctly |
| v6 push CoS-on iperf-6g            | 5.32 Gbps | 0 | shaped correctly |
| v6 push CoS-on iperf-9g            | 7.90 Gbps | 0 | shaped correctly |
| v6 push CoS-on iperf-12g           | 10.1 Gbps | 0 | shaped correctly |
| v4 reverse CoS-on (all classes)    | 19-23 Gbps | varies | reverse path uncapped |
| v6 reverse CoS-on (all classes)    | 13-21 Gbps | varies | reverse path uncapped |
| failover (min interval)            | not run   | n/a | fw0 helper down, no second active node |

## Notes / blockers encountered

**fw0 helper segfault** — `xpf-userspace-dp` worker thread crashes at
IP offset `0x32a4b6` (`core::ptr::drop_in_place<CoSBatch>`) on every
restart. Six segfaults captured across three restart attempts in
`fw0-helper-segfaults.log`. Faulting instruction is
`mov 0x18(%rbx),%r14` with `%rbx == NULL` — a null CoSBatch pointer
reaches Drop. fw1 with the same binary hash runs cleanly.

`userspace-dp/src/afxdp/cos/queue_service.rs` has had zero commits
since `f0081b1f` (2026-04), so the regression is unlikely to be
directly caused by the DPDK retirement chain. The most likely
indirect triggers (in proximity order to dataplane wiring) are
#1516 (grpcapi probe migration, `265d6de7`) and #1521 (maps_sync
decouple, `1f39f79d`).

Recommendation: bisect on the loss userspace cluster between
`902a20ed` (sibling worktree's last known-good deploy from
2026-05-26) and `936b076d`, with the CoS apply-script run after
every deploy. Use `0x32a4b6` as the fingerprint for "still broken".

#1530 and umbrella #1525 stay OPEN until the fw0 helper regression
is identified, fixed, and a clean G5 smoke matrix runs end-to-end
on the loss userspace cluster.

SMOKE-FAILED issue comment posted on #1530 on 2026-05-26.
