# xpf Testing Procedures

## Quick Reference

| Test | Command | Duration | When to Run |
|------|---------|----------|-------------|
| Unit tests (Go + Rust) | `make test` | ~minutes | Every code change |
| Go unit tests only | `make test-go` | ~30s | Go-only change |
| Rust dataplane tests only | `make test-rust` | ~minutes | userspace-dp change |
| Connectivity | `make test-connectivity` | ~60s | After deploy |
| Failover | `make test-failover` | ~120s | Cluster/VRRP/session sync changes |
| Hard crash | `make test-ha-crash` | ~120s | Cluster state machine changes |
| Private RG | `./test/incus/test-private-rg.sh` | varies; three raw deploys for `full` | Private RG election changes |
| Restart | `make test-restart-connectivity` | ~30s | Shutdown/startup changes |

## Test Categories

### 1. Unit Tests (`make test`)

`make test` runs BOTH suites (#4006): the Go suite (`make test-go`) and
the Rust userspace-dp cargo suite (`make test-rust`). A failure in either
fails `make test`. Before #4006 this target ran only the Go suite, so a
Rust dataplane regression — a forwarding / CoS / NAT / session break in
the ONLY runtime forwarding path (#1373/#1476) — passed `make test`
green. The Go leg is ~30s; the Rust leg compiles + runs a few thousand
tests in `--release` and takes a few minutes. A second Rust test leg
(#9499) runs the frame, NAT, session and checksum tests in the default test
profile, where integer overflow panics: a release build wraps silently, so
without it a wrap failed a test only if the test asserted the exact value.
Measured on a loaded host: ~3.5 min cold build, ~65 s run.

**Go suite** (`make test-go`) — 880+ tests across 30 packages. Covers:
- Config parser (hierarchical + flat set syntax)
- Config compiler (Junos AST -> typed structs)
- Cluster election logic (dual-active, preempt, non-preempt)
- VRRP state machine
- Session sync protocol
- Address book compilation
- NAT rule compilation

**Rust suite** (`make test-rust`) — `cargo test --release --bins --tests`
for `userspace-dp` (a binary-only crate, so `--bins` reaches the bin's
unit tests and `--tests` adds any integration tests), run with
`--test-threads=1` to avoid the intermittent `__skb_wait_for_more_packets`
socket-test hang. This is the primary correctness gate for packet
forwarding, CoS shaping, NAT, and session handling. Benches are excluded
(criterion's `harness = false` rejects `--test-threads`). Note (#5190): no
make target or CI job runs `cargo bench`, and only `prefix_set_lookup` and
`runtime_view_refresh` emit a failing verdict — every other bench prints
measurements for a human and exits 0 regardless, so a `cargo bench` exit
status is not a perf gate.

**What `--test-threads=1` does and does not buy you (#6952).** It
serializes libtest's test SLOTS; it does not serialize threads a test body
spawns, so it cannot make an intra-test deadlock safe. Read it as a rate
reducer for the socket-test hang, never as a correctness guarantee, and
never as evidence that a wedge is a parallelism artifact. A second wedge
that this flag appeared to "fix" — three `wg::engine` tests hanging under
a plain parallel `cargo test` — was root-caused (2026-08-28) as a
single-thread `RwLock` self-deadlock (a read guard held across a
`reconcile_peers` that takes the write guard on the same lock) and is now
FIXED rather than worked around.

**When a run wedges (`rc=124`), measure before theorising.** Sample
`utime+stime` from `/proc/<pid>/stat` over 5s: non-zero means spinning
(oversubscription/starvation), ZERO means every thread is parked and it is
a real deadlock that no thread-count change will fix. Then dump
`gdb -p <pid> -batch -ex 'thread apply all bt'` and name the actual wait.
`/proc/<pid>/task/*/comm` carries the libtest test name (truncated to 15
chars) and is inherited by threads the test spawns, so it identifies which
test owns each parked thread. Details and the `run_bounded` pattern that
turns such a wedge into a NAMED failure: `docs/engineering-style.md`.

**Must pass before any commit.**

### 2. Connectivity Tests (`make test-connectivity` or `./test/incus/test-connectivity.sh`)

End-to-end network validation for standalone and cluster deployments.

Tests:
- Service health (xpfd systemd unit active)
- Heartbeat and fabric link connectivity (cluster)
- RETH VIP reachability (IPv4 + IPv6)
- Cross-zone routing (LAN -> WAN gateway)
- SNAT through firewall (LAN -> internet via 1.1.1.1)
- IPv6 end-to-end (ping + iperf3 TCP)
- IPv4 TCP throughput (iperf3)
- mtr path validation (traffic traverses firewall)

Prerequisites:
- Cluster VMs running (`make cluster-create && make cluster-deploy`)
- iperf3 server at 172.16.100.200 (for TCP tests)

### 3. Failover Test (`make test-failover` or `./test/incus/test-failover.sh`)

Validates HA failover survives fw0 reboot with active iperf3 traffic.

Sequence:
1. Start iperf3 on cluster-lan-host (IPv4 + IPv6)
2. Record initial throughput
3. Reboot xpf-fw0 (primary crash)
4. Wait for fw1 to take over (VRRP MASTER)
5. Verify iperf3 continues (session sync preserves TCP)
6. Wait for fw0 to rejoin and failback
7. Verify iperf3 still running (double transition)

**Critical checks (12/12 must pass):**
- iperf3 sessions survive reboot
- VIPs migrate to fw1 during reboot
- VIPs migrate back to fw0 after rejoin
- Throughput > 1 Gbps throughout
- Session sync completes on fw0 rejoin

**Must pass for any cluster/VRRP/session sync changes.**

### 4. Hard Crash Test (`make test-ha-crash` or `./test/incus/test-ha-crash.sh`)

Tests crash recovery scenarios beyond clean reboot.

Scenarios:
- Force-stop VM (`incus stop --force`) — simulates power failure
- Daemon stop (`systemctl stop xpfd`) — exercises graceful shutdown's inactive
  RG publication and dataplane teardown, not lease expiry. If `update_ha_state`
  receipts stop, the helper's receipt-anchored 10s lease is the fail-closed
  forwarding backstop.
- Multi-cycle crash recovery — repeated crashes verify no state leak

A failed `incus start` after a force-stop is a FAIL that names the `incus`
error. The harness then skips the 90 s xpfd wait, so one cause records one
FAIL. Every node the harness starts, including in the final health check,
has its clock resynced from host UTC (#11872).

#### Restoring fw0 between phases

`test-ha-crash.sh` and `test-restart-connectivity.sh` move RG0-2 back to
fw0 after each phase that moved them, through the shared
`deploy_restore_fw0_primary` in `test/incus/deploy-lib.sh` (#18523). It moves
one RG at a time. It re-requests the yield from fw1 only while fw1's own view
still claims the RG, and polls until the RG is restored. An RG counts as
restored only when both nodes' own views agree: fw0 reads `node0 primary`,
and fw1 reads `node1 secondary` or `secondary-hold`. A dual-primary RG, or an
unreadable fw1, is not restored.

| Variable | Default | Meaning |
|---|---|---|
| `RESTORE_FW0_WAIT` | 60 | Seconds to keep re-requesting before giving up. |
| `RESTORE_FW0_BUDGET` | 30 | Seconds a healthy restore may take. Healthy restores take 9-16 s, with one request per RG and no refusal. |

A value that is not a whole number of seconds falls back to the default and
prints an info line.

Each restore records exactly one verdict:

- **PASS** "fw0 already primary", or "fw0 restored as primary in Ns (R
  request(s), 0 refused)": no refusal, and within `RESTORE_FW0_BUDGET`.
- **FAIL** "fw0 restored only after Ns": the cluster was restored, but a
  request was refused or the restore took longer than `RESTORE_FW0_BUDGET`.
  The run continues on the restored cluster, but the run is not healthy. A
  refused or slow restore is the #18521 class, for example a half-open
  session sync or a demotion barrier fence that has not been discharged
  ("session sync barrier fenced ... no re-prime has been acked on it yet").
  Do not raise the budget to make this pass; the FAIL names the last refusal.
- **FAIL** "could not restore fw0 as primary within Ns":
  `RESTORE_FW0_WAIT` ran out. At preflight, both harnesses stop here.

`deploy-lib-selftest.sh` drives this restore with a mocked `incus` and clock
(`test_restore_fw0_verdict_18523`).

### 5. Private RG Election Test (`./test/incus/test-private-rg.sh`)

Validates private-rg-election feature (VRRP elimination) on the shared `loss`
cluster. Use the destructive cluster-cell runner; `full` performs three raw
deploys (private mode, legacy VRRP mode, and the saved file configuration) and
can take substantially longer than a single deploy.

Modes:
- `full` — Snapshot `CONF`, enable and test private mode, disable and test
  legacy mode, then restore and redeploy the saved config if the saved
  bytes are restored successfully.
- `enable` — Enable private-rg-election and validate; leave it enabled.
- `disable` — Disable and verify VRRP returns; leave it disabled.
- `check` — Inspect current state.

Tests with private-rg-election enabled:
- No VRRP instances running
- Zero VRRP multicast on data interfaces
- VIPs present via directAddVIPs
- Full IPv4/IPv6 connectivity
- Manual failover works

Tests with private-rg-election disabled:
- VRRP instances start and reach MASTER
- VIPs present via VRRP
- Full connectivity preserved

The `full` cleanup redeploys `CONF` and attests its file-derived mode on both
nodes after restoring the saved bytes. A failed restore skips redeploy, keeps
the private snapshot, and prints its recovery path. It does not restore
configuration databases or rollback history, nor revert binaries replaced by
the raw deploy. The raw deployment removes `/etc/xpf/.configdb`,
`/etc/xpf/rescue.conf`, and numbered rollback slots. The shared cluster is
temporarily in legacy mode during the cycle; `SIGKILL`, host loss, or another
interrupt during cleanup can leave it in legacy or split mode. Do not run
against an unattended cluster.

### 6. Restart Connectivity Test (`make test-restart-connectivity`)

Restarts xpfd on fw0 in HA mode while pinging through the cluster, and
asserts no more than `MAX_LOST_PINGS` (default 2) lost pings per restart, over
`RESTART_CYCLES` (default 3). It guards the #75 regression (neighbor prewarm
must run after VRRP MASTER). It is not a zero-loss or hitless-restart gate:
HA mode does not do hitless restart.

Between cycles it restores fw0 as the owner of every RG with the same
verdict and the same `RESTORE_FW0_WAIT` / `RESTORE_FW0_BUDGET` knobs as the
hard crash test (see "Restoring fw0 between phases" above).

### 7. Active/Active Split Test (`make test-active-active`)

Moves RG1 (WAN) to fw1 while RG2 (LAN) stays on fw0, then checks that an
iperf3 stream survives the split through fabric forwarding and the
reunification. The split itself is scored from both nodes' own
`show chassis cluster status` by `deploy_active_active_split_verdict`
(`test/incus/deploy-lib.sh`, #18523):

- **Ownership**: RG1 is `primary` on node1 in both views, and node0 is
  `secondary` or `secondary-hold`. RG2 is `primary` on node0 in fw0's view
  and non-owning in fw1's view.
- **Forwarding**: each node's own `Forwarding: rg-active=` line. RG1 is
  `active` on fw1 and `inactive` on fw0; RG2 is the reverse. The daemon
  prints this line for every RG in both election modes, so the check is the
  same in private-RG and legacy VRRP-backed mode.
- A `-- DIVERGENCE: ...` suffix on any of these lines is a FAIL that quotes
  the suffix (#7367). A missing row or line is a FAIL, never a skip.

## Known Issues and Workarounds

### Deploy doesn't update active config (raw path)
**Issue:** `XPF_DEPLOY_FAST=1 make cluster-deploy` (raw path) pushes `xpf.conf` but the daemon loads from the configstore DB (`active.json`). Config changes in `xpf.conf` are ignored on subsequent deploys. (Since #9486 the default deb deploy preserves node config and never pushes `xpf.conf` — this issue cannot occur there.)
**Fix:** Deploy script now clears `.configdb/` after pushing config (fixed in `cluster-setup.sh`, raw path).
**Workaround:** Manually run `rm -rf /etc/xpf/.configdb` on VMs before restart.

### IPv6 SNAT requires explicit ::/0 rule
**Issue:** SNAT rule `source-address 0.0.0.0/0` only matches IPv4. IPv6 traffic passes without SNAT, causing return path failures if the upstream lacks a route to the internal prefix.
**Fix:** Add a separate rule with `source-address ::/0` for IPv6 SNAT.

### iperf3 session count display
**Issue:** `make test-failover` may report 0 established/synced sessions due to display timing. This is a test script issue — the actual session sync works correctly (proven by TCP survival).

## Debugging Tips

### VRRP not starting
1. Check configstore DB: `cat /etc/xpf/.configdb/active.json | python3 -m json.tool | grep private-rg`
2. If stale: `rm -rf /etc/xpf/.configdb && systemctl restart xpfd`
3. Check logs: `journalctl -u xpfd | grep "vrrp:"`
4. Verify interfaces exist: `ip link show | grep ge-0-0`

### IPv6 TCP failing but ping works
1. Check SNAT rules: `show security nat source rule-set lan-to-wan`
2. Verify IPv6 SNAT rule exists with `::/0`
3. Check sessions: `show security flow session destination-prefix <addr>`
4. tcpdump on both interfaces to trace where packets stop

### VIPs missing after failover
1. Check RG state: `show chassis cluster status`
2. Check interface addresses: `ip addr show ge-0-0-0` / `ip addr show ge-0-0-1`
3. Reconcile runs every 2s — wait and check again
4. Force reconcile: `systemctl restart xpfd`

### Dual-active detection
1. Both nodes primary: check `show chassis cluster status` on both
2. Heartbeat: `ping 10.99.0.X` between nodes
3. Non-preempt mode resolves by effective priority then node ID
4. Logs: `journalctl -u xpfd | grep "Dual-active"`
