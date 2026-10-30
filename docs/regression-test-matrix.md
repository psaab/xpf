# Forwarding, Performance and HA Regression Matrix

This is the matrix a forwarding-plane, session, HA or sync change runs before it
merges. It also sets the cadence for re-proving the clusters themselves. Every
row exists because a real defect got past the checks that existed before it.
The **Catches** column names the defect, so a row is never deleted as
"redundant" without first naming what else would catch that defect.

It complements, and does not replace:
- `docs/testing-procedures.md`: how to run each harness;
- `docs/ha-cluster-test-plan.md`: the legacy topology;
- the gate rules in `.claude/skills/campaign/SKILL.md`: who gates what, and
  lock discipline.

**When to run it**
- **Every PR** touching `userspace-dp/`, `pkg/dataplane/`, `pkg/cluster/`,
  `pkg/vrrp/` or `pkg/daemon/` HA wiring: tiers 0–2, plus the tier-3 rows its
  area names.
- **After every merge wave**, on `loss` and `tcp`: tiers 2–4 against the
  deployed master. That re-proves the clusters, not just the PR.
- **A failed row blocks the merge.** A VOID row is not a pass: fix the
  precondition and rerun.

## Tier 0: build and hermetic (no cluster)

| ID | Run | Pass | Catches |
|---|---|---|---|
| B1 | `make test` (Go + Rust suites) | the failing set equals master's recorded pre-existing set, with no new names | ordinary regressions |
| B2 | `cd userspace-dp && cargo build --release --bin xpf-userspace-dp` | builds | **`cargo test` does not see release-only lints**: a test-only re-export failed `make deb` with `unused_imports` (#18520) |
| B3 | `make lint-rust-baseline` | no NEW diagnostics | a dead getter that turns the CI ratchet red (#18520 review) |
| B4 | `make harness-census`, `make test-*-lib` for any touched harness library | green | an unregistered or broken harness |
| B5 | Mutation-check every new cell: revert the fix in place (file copy, never `git stash`) and confirm the cell goes red | each new cell fails on revert | a cell that cannot detect its own defect (several PRs on 2026-10-29) |

## Tier 1: deploy and identity

| ID | Run | Pass | Catches |
|---|---|---|---|
| D1 | Build the deb in the PR's own worktree and deploy it from that same worktree. Commit nothing in that worktree between the deploy and the last gate | `exe_check=MATCH` on every ledger row | **a shared worktree cross-contaminates the deploy manifest**: deploying cluster A from the worktree that deployed cluster B turns B's rows VOID (`exe_check=MISMATCH`). **The manifest is keyed to the checkout's HEAD**: a merge or commit after the deploy VOIDs every later row ("deploy attestation manifest belongs to a different checkout"). Land harness changes before deploying |
| D2 | The deb version is higher than the installed one | the deploy succeeds | apt refusing a downgrade. Build with the default version after the branch is current with master, or deploy a bumped `DEB_VERSION` by path, never by passing `DEB_VERSION` to the locked make |
| D3 | After a deploy, node0 is primary for every RG, and CoS is re-applied if the gate uses CoS | `show chassis cluster status` | deploy wipes CoS; a stale owner after a prior run |
| D4 | **Unit identity.** On every node: `systemctl show xpfd -p FragmentPath -p KillMode` | the effective unit matches the repo/package unit (`KillMode=mixed` since #18213) | a stale `/etc/systemd/system/xpfd.service` from an older raw setup shadowing the packaged unit. On loss and tcp it kept `KillMode=control-group`, so systemd killed the helper at SIGTERM and every stop/restart test measured a different shutdown than production (2026-10-30) |

## Tier 2: forwarding and performance (loss and tcp)

Record `/proc/loadavg` next to every throughput number: the orchestrator's and the firewall VMs' and LAN host's (`make perf-matrix` records all four). The VMs run on the cluster's incus remote, not on the orchestrator. Judge each cluster only
against its own band below, never against another cluster's. Use each env's
`IPERF_TARGET4/6` (loss `172.16.80.200`, tcp `172.16.80.210`, udp
`172.16.80.211`), never `172.16.100.x`.

**Baseline bands** (Gbit/s, 20 s runs). `make perf-matrix` uses port 5211,
the unshaped class; port 5201 is the lab CoS config's 100 Mbit/s exact class
(#9691), so never measure on it while CoS may be applied. The rows below were
taken on 5201 with CoS not applied (a fresh deploy wipes it), which is
equivalent. They record what a build reached, with date and loadavg; replace
a row when a merge wave moves it. Bands exist only for the cells shown.

| Cluster | Build | v4 -P1 | v4 -P8 | v4 -P12 | v6 -P8 | Orchestrator loadavg |
|---|---|---|---|---|---|---|
| loss | integ6, 2026-10-29 (#18520 + #18533 + HA fixes) | 4.3–4.9 | 17.9–18.8 | 17.0–19.4 | 9.8–20.2 | 3–8 |
| tcp | integ6, 2026-10-29 | 12.6–18.6 | 39.0–41.0 | 37.8–40.0 | 39.1–41.0 | 3–8 |
| loss | master `09a2b664be`, 2026-10-29 (before #18520) | ~2.4 | 11.6–14.4 | — | — | — |

Loss v6 `-P8` spreads widely (9.8–20.2) because of how 8 flows hash onto 6
workers. A single v6 run below 9 Gbit/s is a re-run, not yet a regression; two
are a regression.

| ID | Run | Pass | Catches |
|---|---|---|---|
| F1 | `make test-connectivity` | no failures other than the known-environment rows (below) | basic forwarding |
| F2 | `make perf-matrix` (v4/v6 × push/reverse × `-P1`/`-P8`/`-P12`, 2 reps; tcp/udp need the lock tuple exported) on the PR build **and** on the master build it is compared with, on the same cluster in the same session | no cell more than 10% below the same cell on master; any cell with a band above stays inside it once master has reached that band. The harness records throughput; this comparison is read from the two summaries | throughput regressions. Loss `-P8` measured 11.6–14.4 Gbit/s on master while cross-worker handshakes never completed (#18520); integ6 lifted it to 18.8, and tcp from ~23.5 to ~40 |
| F3 | **Session-state health.** During a 20 s `-P8` run, check that the serving worker's rows are Established. Today: profile the hot worker (`perf record --call-graph lbr`); `cache_hit_handshake_progress`, `node_served_evidence` and `probe_record_with_origin` must be **absent**, and `SessionKey` hashing should stay well below 10% of cycles | evidence-scan symbols absent | **cross-worker handshakes never completing** (#18520). Flows sat on the 20 s opening window, and every packet paid an evidence scan worth about 40% of worker cycles. The CLI `Timeout` column reads the shared view, which lags the worker tables (#18530), so it is not this row's oracle until #18530 is fixed |
| F4 | Profile the hot worker under `-P8` (`perf record --call-graph lbr -p <helper pid>`) and keep the top 25 symbols with the run | no new top-10 symbol without an explanation | per-packet cost creep. Loss `SessionKey::hash` was 3.3% on 2026-10-19, 16.9% on 2026-10-29, 9.8% after #18520 |
| F5 | New flows during a split (WAN RG on one node, LAN RG on the other), v4 and v6, to the WAN target **and** via a non-default static | 0% loss | split nodes dropping new WAN flows (#18517), stamped fabric punts dropping as Invalid (#18518), a non-default static ending in NoRoute (#18517 review) |
| F6 | **Stalls.** The same `make perf-matrix` run | `RESULT: PASS`: no run errors, no 1 s interval under 25% of the run's peak (healthy runs never dip below 74%), no stream under 1 Mbit/s in any interval | **"the iperfs stop"**: a single stream dying while the others absorb its share keeps the aggregate healthy, so only a per-stream, per-interval check sees it. `make perf-matrix-lib` pins the verdict on fixtures |

## Tier 3: HA (loss and tcp; destructive targets self-lock)

Resync node clocks after any crash reboot: the loss lab has no NTP
(`failover_resync_node_clocks`, #11872).
Before pairing fw0 and fw1 journal times, measure the skew (on 2026-10-30 fw1 ran 66.8 s behind fw0 on loss); a cross-node timeline without that offset produced a wrong diagnosis once.

| ID | Run | Pass | Catches |
|---|---|---|---|
| H1 | `make test-failover` | PASS, including the crash takeover **and** the RG1 failback split, with every stream's last-good second at the end of the run | streams dying on takeover because synced sessions carried truncated zone ids (#18515); the failback split killing established SNAT streams. Three separate mechanisms did that (#18531), and the row only passes when none fire: the LAN node revoked its promoted row against the fabric pseudo-egress and synced the Close to the WAN owner; the WAN owner purged its alias rows as translated-synced when the reply arrived over the fabric link; and the returning owner judged a WAN reply to the SNAT address LocalDelivery and tore the session down at the host-inbound gate |
| H2 | `make test-ha-crash` | PASS on all phases | a stuck restore after a peer restart (#18521 fence and re-prime storm); a lost config-apply ACK blocking RG0 failover (#18521) |
| H2a | **Restore budget**: `test-ha-crash` and `test-restart-connectivity`, the targets that carry `RESTORE_FW0_BUDGET` (#18524) | the post-run restore to node0 takes ≤ `RESTORE_FW0_BUDGET` (default 30 s) with no refused failover. Healthy restores took 9–16 s on 2026-10-29 | a restore that only succeeds on its fourth retry hides a fence or barrier refusal ("demotion peer barrier failed: session sync barrier fenced") that the next real failover hits too (#18523, #18521) |
| H3 | `make test-double-failover` | PASS on both transitions; per-stream data shows every stream resumes after **each** takeover | takeover by a node whose replicas came from a rejoin bulk: on 2026-10-30 the second takeover killed every stream on loss (2 of 4 on tcp) while the first survived |
| H4 | `make test-restart-connectivity` | PASS, no cycle over the loss budget, and the outage does not grow across cycles | daemon-restart blackholes: an orderly private-RG stop handed nothing to the peer and detection was padded by the stopping node's own sync backlog (#18540); an outage that grows cycle over cycle points at state carried between cycles |
| H5 | `make test-active-active` | PASS | split-RG forwarding; a verdict that rejected `secondary-hold` (#18523) |
| H6 | **Split dwell.** Move RG1 to the peer, hold the split ≥ 90 s with `-P8` running, move it back; repeat in the other orientation | 8/8 streams survive both moves | standby replicas reaped at 3 × the opening window (60 s) before they are needed (#18520). H1's failback lands about 64 s after rejoin, right at that edge, so a dwell longer than 60 s is required |
| H7 | **Sync health after every RG move and restart.** Session sync is connected on both nodes within 5 s; a manual failover is admitted within one admission window (no `peer config stale`, no fence refusal); `Sessions stale-config-ignored` does not climb | as stated | a half-open sync connection surviving 56 s (#18521); a fence that never discharges; a config ACK credited then wiped by the peer's new-boot BulkStart (#18521); re-pushes moving the config epoch (#18521 review); the primary ignoring standby epochs (#18526) |
| H8 | **Revocation symmetry.** After H1, compare `show security flow session` on both nodes for the iperf flows | no session row survives on one node whose twin the other node closed | a Close emitted for an alias-only owner keyed on the translated tuple, which left the LAN node's original-tuple row alive and still translating (#18531 review) |
| H9 | **Split-window streams.** In H1's per-stream data, the window where `test-failover` holds RG1 apart from RG0/RG2 (the #11581 isolated-failback slice, 63–73 s) | no stream dies in or after the window; aggregate at or above the split-RG fabric ceiling (`docs/fabric-performance-optimizations.md`: about 2.0–3.5 Gbit/s on loss; about 6 Gbit/s on tcp in an RG1-only control), judged separately from the whole-run average | streams killed at the split-RG moves (#18531/#18535) read as "slow" because every flow crosses the copy-mode fabric for the whole window; a killed iperf3 scored as 0.0 Gbit/s plus a collapse (#18543). The fabric ceiling itself is #12655 |

## Tier 4: soak and cadence

| ID | Run | Pass |
|---|---|---|
| S1 | `-P8` for 30 min on loss with one manual RG move every 5 min | no stream dies; throughput within band |
| S2 | After every merge wave: tiers 2–3 on both clusters against deployed master, results appended to the cluster's baseline index | as stated |

## Known-environment rows (not product failures; re-verify before excusing)

- **tcp external IPv4 (1.1.1.1, 8.8.8.8).** The upstream behind 172.16.50.1
  does not forward for the tcp cluster's source; the firewall reaches its
  gateway directly. Verify with the gateway ping before excusing the row.
- **External IPv6 from the LAN host** (`2607:f8b0:...`): an upstream issue the
  campaign skill already lists as known.
- **#18212 fabric/control host pings** (fw0↔fw1 on 10.99.x) fail on loss, tcp
  and udp.
- **tcp host SR-IOV VFs.** The host's dracut default network must not manage
  the VF netdevs. `/etc/systemd/network/05-xpf-sriov-vf-unmanaged.network`
  marks `eno1v*`/`eno2v*` unmanaged. Without it a force-stopped VM cannot
  restart: "All virtual functions on parent device mlx1 are already in use".

## Reading results

- **FAIL** is attributable: the binary was confirmed to be the build under
  test.
- **VOID** means the measurement cannot be attributed (`exe_check` mismatch,
  a precondition, a harness fault). Fix the cause and rerun; a VOID is never a
  pass and never a regression.
- A stream that survives the takeover but dies later is still a death. Check
  the per-stream last-good second. Many streams stopping in the same second
  points at an event (a delete, a reap or a role change), not at load.
