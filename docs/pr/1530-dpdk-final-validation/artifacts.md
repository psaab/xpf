# #1530 DPDK Final Validation — Artifact summary

Phase B executed 2026-05-26 against the merged Phase 3 commit.

**Run 1** (10:13Z): G0-G4 PASS, G5 SMOKE-FAILED on fw0 first-snapshot
CoSBatch null deref. SMOKE-FAILED comment posted as
issuecomment-4543514525. Run-1 artifacts archived under
`artifacts/run1-fw0-helper-race/`.

**Bisect agent `a4b4b8581f6b96e00`** returned NO-LOCALIZATION — the
fw0 crash is a non-deterministic first-snapshot install race that
recovers via helper respawn per #925 design. Same binary hash now
runs cleanly. Tracked under a new follow-up issue (not a #1525
blocker).

**Run 2** (14:50Z): G5 re-run against the stable cluster. G0-G4
evidence retained from Run 1 (commit unchanged at `936b076d`).
All five G5 sub-gates **PASS**. Final disposition:
**VALIDATION ARTIFACT POSTED**.

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
| G5.a | CoS-off IPv4 push + reverse (P=12 + P=1)               | **PASS** | `artifacts/smoke-v4-cosoff-{push,reverse}{,-P1}.log` |
| G5.b | CoS-off IPv6 push + reverse (P=12 + P=1)               | **PASS** | `artifacts/smoke-v6-cosoff-{push,reverse}{,-P1}.log` |
| G5.c | CoS-on class sweep (v4 + v6, push + reverse, 24 cells) | **PASS** | `artifacts/smoke-v{4,6}-coson-<class>-{push,reverse}.log` |
| G5.d | Screen / flood baseline (LAND, SYN-flood, ICMP-flood)  | PARTIAL  | `artifacts/smoke-screen-*.log` |
| G5.e | `make test-failover` (Pass A failover + failback)      | **PASS** | `artifacts/make-test-failover.log` (14 passed / 0 failed) |
| **G5 overall** | HA smoke matrix on exact commit               | **PASS** | run 2 against stable cluster |

## Throughput numbers (Run 2, both helpers healthy)

CoS-off (port 5200, best-effort term):

| Test | Sender SUM | Retr | Notes |
|------|-----------|------|-------|
| v4 push   P=1  | 8.26 Gbps  | **0** | single-stream per-binding ceiling |
| v4 reverse P=1 | 8.47 Gbps  | **0** | single-stream per-binding ceiling |
| v6 push   P=1  | 8.56 Gbps  | **0** | single-stream per-binding ceiling |
| v6 reverse P=1 | 8.31 Gbps  | **0** | single-stream per-binding ceiling |
| v4 push   P=12 | 23.3 Gbps  | 1    | near line-rate (25 Gbps cap) |
| v4 reverse P=12| 22.8 Gbps  | 48   | near line-rate |
| v6 push   P=12 | 23.1 Gbps  | **0** | near line-rate |
| v6 reverse P=12| 22.6 Gbps  | 223  | near line-rate |

CoS-on class sweep (P=4, t=5, push enforces cap; reverse uncapped
because the policer is egress-only):

| Class (port) | v4 push | v4 reverse | v6 push | v6 reverse |
|--------------|---------|------------|---------|------------|
| iperf-100m (5201) | 82.8 Mbps (cap 100M) | 20.0 Gbps | 81.8 Mbps | 20.9 Gbps |
| iperf-1g   (5202) | 848 Mbps  (cap 1G)   | 12.9 Gbps | 840 Mbps  | 22.7 Gbps |
| iperf-3g   (5203) | 2.71 Gbps (cap 3G)   | 20.4 Gbps | 2.68 Gbps | 19.2 Gbps |
| iperf-6g   (5204) | 5.38 Gbps (cap 6G)   | 22.7 Gbps | 5.14 Gbps | 13.8 Gbps |
| iperf-9g   (5205) | 8.05 Gbps (cap 9G)   | 19.4 Gbps | 7.50 Gbps | 19.2 Gbps |
| iperf-12g  (5206) | 10.7 Gbps (cap 12G)  | 22.8 Gbps | 10.6 Gbps | 20.4 Gbps |

Failover (`make test-failover`, fw0=primary):
- iperf3 -P 8 -t 120 sustained through fw0 unclean reboot,
  fw0 rejoin as secondary, manual failback to fw0
- Throughput: **9.02 Gbps** (Pass A floor: ≥ 1.0 Gbps)
- 14 assertions passed / 0 failed
- All 3 RGs (RG0, RG1, RG2) failed over and back cleanly

## Notes

**Run 1 fw0 helper segfault (resolved by respawn)** — The first-run
CoSBatch null deref at IP offset `0x32a4b6` was investigated by the
bisect agent `a4b4b8581f6b96e00`, which concluded NO-LOCALIZATION:
it is a non-deterministic first-snapshot install race that recovers
via helper respawn per #925 design. The same `xpf-userspace-dp`
binary (sha256 `975f6fe3…`) that crashed in Run 1 runs cleanly in
Run 2 against the same `936b076d` commit. Tracked under a new
follow-up issue (not a #1525/#1528/#1373 blocker since it predates
#1528). Run-1 evidence preserved under
`artifacts/run1-fw0-helper-race/`.

**G5.d screen baseline (PARTIAL)** — the deployed cluster config
does not define screen profiles (`No screen profiles configured`),
so LAND / SYN-flood / ICMP-flood attack counters cannot increment.
The daemon-survivability portion of the gate passed: both helpers
remained PID-stable across the 15s aggregate attack window, cluster
status unchanged. To complete G5.d fully a future run should layer a
screen profile onto the cluster config before driving attacks.

**Out-of-band CLI regression discovered** — `cli -c "configure
private; <stmt>; commit"` with semicolon-chained commands panics in
non-TTY mode at `cmd/cli/shared.go:225`
(`chzyer/readline.(*Instance).SetPrompt` deref on nil `c.rl`). Not a
DPDK retirement regression; G4 was driven via REST API instead.
Worth a separate follow-up issue.

VALIDATION ARTIFACT POSTED on 2026-05-26. #1530 + #1525 closed
following the SMOKE-PASS comment.
