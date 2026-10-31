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
  precondition and rerun. The cells listed under "Known product failures
  (tracked)" are judged against the cluster's recorded master baseline
  instead, and a "Known environment rows" cell is excused only while its
  off-path control fails in the same run.

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
a row when a merge wave moves it. Bands exist only for the cells shown. Each
cell is `push / reverse` (`sum_received`), the min–max of 6 runs: integ8,
integ9 and integ10, 2 repetitions each.

| Cluster | Build | v4 -P1 | v4 -P8 | v4 -P12 | v6 -P8 | Orchestrator loadavg |
|---|---|---|---|---|---|---|
| loss | master after the 2026-10-30 wave (integ8/9/10) | 4.6–5.5 / 4.8–4.9 | 14.1–19.1 / 16.7–21.1 | 18.2–21.7 / 15.7–20.8 | 13.7–22.8 / 17.4–19.7 | 0.3–5.9 |
| tcp | master after the 2026-10-30 wave (integ8/9/10) | 14.1–19.6 / 12.4–17.6 | 38.5–39.7 / 40.0–41.5 | 37.5–38.9 / 37.9–39.7 | 37.0–39.5 / 39.3–41.2 | 0.4–5.6 |
| loss | historical: master `09a2b664be`, 2026-10-29 (before #18520), push only | ~2.4 | 11.6–14.4 | — | — | — |

Loss `-P8` push spreads widely (v4 14.1–19.1, v6 13.7–22.8) because of how 8
flows hash onto 6 workers (per-stream placement is an open item). The lower
edges overlap the pre-#18520 regression range. For these two cells the
per-repetition band floor still catches a stranding worse than master's own
placement spread, but it cannot tell that spread from the pre-#18520
regression; F2's best-of-reps ≥ 90% comparison is what catches that. A
single loss `-P8` repetition below the band floor (v4 14.1, v6 13.7) is a
re-run, not yet a regression; two are a regression.

| ID | Run | Pass | Catches |
|---|---|---|---|
| F1 | `make test-connectivity` | no failures, except that a cell listed under "Known product failures (tracked)" (below) is judged against the cluster's recorded master baseline, and a "Known environment rows" cell is excused only when its off-path control, re-run in the same run, also fails | basic forwarding |
| F2 | `make perf-matrix` (v4/v6 × push/reverse × `-P1`/`-P8`/`-P12`, 2 reps; tcp/udp need the lock tuple exported) on the PR build **and** on the master build it is compared with, on the same cluster in the same session | for every cell, the PR build's best repetition is at least 90% of master's best repetition, **and every repetition** stays inside the cell's band once master has reached that band (a regression that shows only in some repetitions, such as an RSS placement that strands flows on one worker, is caught by the per-repetition floor, not by best-of-reps; for loss `-P8`, one repetition below the floor is re-run first, see the note under the bands). Best-of-reps is used because single runs of the same build spread wider than 10% (loss v6 `-P8`: 9.8–20.2 Gbit/s in one session); run 3 reps (`PERF_MATRIX_REPS=3`) whenever a cell's two reps differ by more than 20% on either build (seen on loss v6 `-P8` at 0.65–0.72 and tcp reverse `-P1` at 0.78–0.79), and judge that cell on the 3-rep best. The harness records throughput; this comparison is read from the two summaries | throughput regressions. Loss `-P8` measured 11.6–14.4 Gbit/s on master while cross-worker handshakes never completed (#18520); integ6 lifted it to 18.8, and tcp from ~23.5 to ~40 |
| F3 | **Session-state health.** During a 20 s `-P8` run, check that the serving worker's rows are Established. Today: profile the hot worker (`perf record --call-graph lbr`); `cache_hit_handshake_progress`, `node_served_evidence` and `probe_record_with_origin` must be **absent**, and `SessionKey` hashing should stay well below 10% of cycles | evidence-scan symbols absent | **cross-worker handshakes never completing** (#18520). Flows sat on the 20 s opening window, and every packet paid an evidence scan worth about 40% of worker cycles. The CLI `Timeout` column reads the shared view, which lags the worker tables (#18530), so it is not this row's oracle until #18530 is fixed |
| F4 | Profile the hot worker under `-P8` (`perf record --call-graph lbr -p <helper pid>`) and keep the top 25 symbols with the run | no new top-10 symbol without an explanation | per-packet cost creep. Loss `SessionKey::hash` was 3.3% on 2026-10-19, 16.9% on 2026-10-29, 9.8% after #18520 |
| F5 | New flows during a split (WAN RG on one node, LAN RG on the other), v4 and v6, to the WAN target **and** via a non-default static | 0% loss | split nodes dropping new WAN flows (#18517), stamped fabric punts dropping as Invalid (#18518), a non-default static ending in NoRoute (#18517 review) |
| F6 | **Stalls.** The same `make perf-matrix` run | `RESULT: PASS`: no run errors, no 1 s interval under 25% of the run's peak (healthy runs never dip below 74%), no stream under 1 Mbit/s in any interval | **"the iperfs stop"**: a single stream dying while the others absorb its share keeps the aggregate healthy, so only a per-stream, per-interval check sees it. `make perf-matrix-lib` pins the verdict on fixtures |
| F7 | **Traceroute through the cluster.** From `$CLUSTER_LAN_HOST` (loss: `cluster-userspace-host`): `mtr -n --report --report-cycles=3 -4 1.1.1.1` and `mtr -n --report --report-cycles=3 -6 2001:4860:4860::8888`, then both again with `-u` (UDP probes). **Same-run control:** ping each destination from the same host | if the control ping fails, F7 is VOID and the ping failure is investigated like any F1 failure (upstream or the product; that ping crosses the firewall): never a pass, never an excuse. Otherwise, judged per sub-criterion: **(a)** hop 1 is the LAN-side reth VIP in both families, never a per-node `169.254.x.x` or `fe80::` RETH address; **(b)** hop 2, the first router past the firewall, answers (loss under 100%), which proves upstream Time Exceeded is un-NATed back to the LAN host; **(c)** ICMP mode only, the final hop is the destination at 0% loss. Later intermediate hops may be silent (upstream rate limits), and `-u` is judged on (a) and (b) only, because a public destination need not answer UDP probes | ICMP Time Exceeded from upstream routers not un-NATed back to the LAN host (every hop past the firewall `???` while ping works), and the firewall's own v4 TTL-exceeded sourced from `169.254.2.1` (#18174, user-reported 2026-10-30). On master before #18556, `test-connectivity`'s validators `check_mtr_linklocal4/6` **assert the defect** (they require the 169.254/16 and fe80::/10 first hop); #18556 replaces them with `check_mtr_reth_vip`, which covers (a)–(c) for ICMP mode. No `test-connectivity` cell runs `mtr -u`, so the `-u` half of F7 is always run by hand |

## Tier 3: HA (loss and tcp; destructive targets self-lock)

Resync node clocks after any crash reboot: the loss lab has no NTP
(`failover_resync_node_clocks`, #11872). H11 is the exception and must never
resync: it reports the skew instead, because the operator's own loop gets no
clock help (`docs/ha-rg-move-correctness.md`).
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
| H10 | **Hitless failover** (#18559; generation drops #18560, crash takeover #18561). In one lock cell (`with-cluster.sh`), from `$CLUSTER_LAN_HOST`: `iperf3 -c $IPERF_TARGET4 -p 5211 -P8 -t 120 -i 0.1 -J` and `ping -D -i 0.01 $IPERF_TARGET4`. **Planned:** for each RG in turn, `cli -c "request chassis cluster failover redundancy-group <N> node <taker>"` (an explicit transfer to `<taker>`; without `node` the command demotes the node it runs on, so run on the taker it moves nothing). Confirm with `show chassis cluster status` that the RG moved; a move that did not happen makes the cell VOID. Wait 10 s, then move it back the same way, and finish with `request chassis cluster failover reset redundancy-group <N>` on both nodes. **Crash:** `incus stop --force` the node that owns the data RGs, then restore it. A VM force-stop leaves the survivor's sync socket half-open, so the sync-recency guard is in play; a process kill closes it and is the easier case. Read every timing on the LAN host's clock only (no cross-node pairing) | **Per PR (HA PRs, master-relative):** run each build 3 times on the same cluster. For each number (per-move lost pings, worst stream stall, crash ping gap), the PR's median is at most master's median plus master's own spread (max − min over its 3 runs, and at least 1 ping or 100 ms), and no stream dies. Master's 3 runs are recorded once per merge wave per cluster, by the first HA PR gated there, and reused until the next wave. Single runs spread too far to compare: the same build's worst stall was 1.0 s in one planned run and 1.9 s in another, and crash declaration varies by design between the 1.0 s threshold and the 2 s sync window. **Target (#18559; tracked until met):** per single-RG move at most 3 pings lost (30 ms), and no stream has two or more consecutive 100 ms intervals under 1 Mbit/s. A stall of 300 ms or more always fails; one of 200–300 ms fails depending on how it aligns with the intervals, so a single minimum TCP retransmit timeout (about 200–230 ms) usually passes. `-i 0.1` is iperf3's finest interval, so this is the resolution the row has. Crash: the LAN host's longest ping gap is at most 1.4 s (the 1.0 s staleness threshold of the lab's 200 ms × 5 heartbeat, plus one 200 ms tick, plus 200 ms to activate), and no stream dies. That bound assumes #18561 stops the sync-recency guard (`maxPeerSyncSilence`, 2 s) from deferring declaration on a half-open socket; on master the guard alone can push it past 2 s | baseline on loss, 2026-10-30, master `2cf76b8d92` plus #18556 (build `848d475531`): three sequential single-RG moves (RG0, RG1, RG2) lost 23 pings in all (failback 26), with the largest single gap 9 pings; a batch move of all RGs lost 20–21; and the worst single-stream stall per run was 1.0, 1.3 and 1.9 s (TCP backoff after short losses). A crash of the owner left a 2.2 s ping gap (one run). Sessions are already on both nodes, so every lost packet is a transition defect: the demote/activate gap, drops on the old owner, generation-stamp drops at each helper publish, the split window between per-RG moves. Scripted versions of both procedures land with #18559 |
| H11 | **One-node RG-move soak** (#18583): `make test-rg-move-soak` (ledger-wrapped, smoke-cells). Issues `request chassis cluster failover redundancy-group <rg> node 0|1` from ONE node, alternating, `SOAK_SLEEP` s after each CLI return, under IPv4+IPv6 `iperf3` and `ping -D -i 0.01` from `$CLUSTER_LAN_HOST`, and NEVER fixes clocks (the preflight reports node1−node0 skew). Per HA PR: `SOAK_MOVES=40 SOAK_SLEEP=5` from node0, then `SOAK_MOVES=40 SOAK_SLEEP=2 SOAK_FROM=1`, PR and master in the same window on the same cluster. Per merge wave on loss: `SOAK_MOVES=200` at `SOAK_SLEEP=5` and at `SOAK_SLEEP=2` | **Correctness (absolute):** no FAIL and no VOID move, and not a void run. A move is correct when the CLI says `transfer committed`; both nodes' own views show the target primary and the other node `secondary`/`secondary-hold` within `SOAK_CONVERGE_S` of the CLI returning and for the rest of the window (no dual-active sample, no revert); each node's `Forwarding: rg-active=` line and each helper's `ha_groups[].forwarding_active` (active and an unexpired lease) agree; the traffic followed (the target's RETH-member counters carry the packets and the LAN host's neighbour entry resolves to the target's MAC); traffic flows in the window's tail; and no stream dies. **Transition cost (master-relative, as H10):** a recovered gap over 1000 ms or stall over 2000 ms scores COST, not FAIL (#18559). Per PR, the PR's COST count and median/p95 worst-stall are at most master's plus master's own spread over the same number of runs, and no new FAIL class appears | the operator's pattern, which no other row runs: on 2026-10-31 loss had fw1 72 s behind with no NTP, and every move to node1 failed fabric auth (`window 60s/90s ahead of ours`) while every move back printed `already primary`. That was 10 FAIL and 10 VOID in 20 moves, and traffic never left node0. The NTP fix is #18584 and peer-skew visibility #18585. With both, on loss (0.0.26140): 200 moves at 5 s all landed, with 5 single-stream stalls of 2.2–6.6 s (COST under today's rule); 200 at 2 s all clean. tcp (30) and udp (40, every RG from node1 at 2 s) all landed. Split-RG moves of RG2 alone run every flow over the fabric while RG2 is away (loss tail about 2.7 against 11.5 Gbit/s), which is expected |

## Tier 4: soak and cadence

| ID | Run | Pass |
|---|---|---|
| S1 | `-P8` for 30 min on loss with one manual RG move every 5 min | no stream dies; throughput within band |
| S2 | After every merge wave: tiers 2–3 on both clusters against deployed master, results appended to the cluster's baseline index | as stated |

## Known product failures (tracked)

None of these is environment. Per PR, each cell is judged against the
cluster's recorded master baseline (the campaign skill's cached baseline,
not a fresh master deploy per PR). A cell green on master and red on the PR
blocks the merge, as in the skill's "failure on any cell that passes on
master = BLOCK". A cell red on both is judged on its parts: F7 per
sub-criterion (a)–(c), and H10 by its numbers, so a PR cannot make a red
cell worse unnoticed. After a merge wave, these are the only cells expected
to be red, until their issue closes; any other red cell is a new failure.

- **H11 transition cost: #18559.** H11's COST verdict (a recovered gap or
  stall over its budget) is this issue's transition cost; H11 judges it
  master-relative, and correctness (FAIL/VOID) absolutely.
- **H10 hitless targets: #18559** (with #18560 and #18561). The row's
  baseline (master plus #18556) misses the targets, so HA PRs are gated on H10's
  master-relative numbers until #18559 closes.
- **MTR / traceroute cells: #18174, fixed by #18556.** Every cluster MTR
  cell in `test-connectivity`: "mtr LAN→WAN gateway (via RETH link-local)",
  "mtr LAN→internet IPv4 (via RETH link-local)", "mtr LAN→internet IPv6
  (via RETH link-local)", and Group11 IPv4/IPv6 MTR. Two of them were excused
  here as an upstream issue. On a build that carries the hop-1 fix, master's
  validators also reject the now-correct VIP first hop ("first hop
  '10.0.6x.1' is not an IPv4 link-local RETH address") until #18556's
  validator lands. Ping to a live destination
  (`1.1.1.1`, `2001:4860:4860::8888`) works in both families while every
  hop past the firewall is `???`. They are row F7.
- **Fabric/control host pings: #18212.** Pings fw0↔fw1 on 10.99.x fail on
  loss, tcp and udp. Host ICMP to the WAN gateway (`172.16.50.1`) failed
  on tcp (integ9, integ10) and on udp, and passed on loss (integ8–10). That
  WAN-gateway leg is #18558, not #18212: tcp's and udp's WAN addresses were
  duplicates on the lab segment, and loss's `.8` is not (see the
  environment row below). The 10.99.x fabric/control pings remain #18212.

## Known environment rows (re-verify before excusing)

Before excusing a cell here, run a control in the same run that takes the
product out of the path, for example the same destination from the incus
host or the orchestrator. If the control passes, the cell is a product
failure.

- **LAN host → internet IPv6 ping (`2607:f8b0:4005:80e::200e`)**, the
  `test-connectivity` cell of that name. The target is dead: from the
  orchestrator, with no firewall in the path, it and `2607:f8b0:4005:814::200e`
  answered 0/2 echo, while `2001:4860:4860::8888` answered 2/2 (2026-10-30;
  the loss LAN host saw the same through the cluster, #18556). The fix is in
  the harness: retarget the cell to `2001:4860:4860::8888` (#18174, done
  in #18556 at `cce3fb4944`). Re-run the off-path control before excusing it
  again; once #18556 merges this row should be deleted.

- **tcp/udp external IPv4 (1.1.1.1, 8.8.8.8): a duplicate WAN address,
  #18558.** The cause is the lab segment, not the product. The fix is a
  renumber (#18575), but **until a cluster has been renumbered live, judge
  these cells on it exactly as before**: over 3 smokes per build, a PR blocks
  only if it fails them in at least 2 more of its 3 runs than master did. The
  row's same-run off-path control is `ha_wan_claim_check` returning status 1
  for the cluster's WAN address (test-connectivity's "WAN IPv4 ... answered
  for only by this cluster" FAIL, or test-failover's VOID reason). A ping from
  the orchestrator or the incus host cannot stand in for it: it does not leave
  from the duplicated address, so it passes either way.

  VLAN 50 (172.16.50.0/24) is shared with non-xpf devices. tcp's
  172.16.50.10 was also held by `18:e8:29:2c:13:7a` and udp's 172.16.50.11
  by `d8:b3:70:8c:f8:44`. Each answered every RFC 5227 ARP probe for its
  address, alongside the RG owner (512/512 probes for .10, 2026-10-31). The
  upstream gateway's ARP entry flipped between the device and the owner.
  Recovery always followed the owner's own ARP to the gateway
  within 1-2 s (8/8), and each outage began about 30 s later, when the
  device refreshed. IPv4 loss was therefore 20-50% on tcp, and up to 80% on
  udp, whose device refreshes more often, while IPv6 stayed clean.
  The "replies miss the session" reading was the device's own return traffic
  reaching the owner while the entry pointed at it. Earlier this row blamed
  "30-55 s after an RG move", but the loss is periodic with no move at all;
  the move's GARP burst only reset the cycle.

  Same-run proof on tcp, with the deployed build unchanged:
  - 2026-10-31 00:21-00:36, reth0.50 v4 `.10` -> `.42` -> `.10`, sampling
    the LAN host's 1.1.1.1 and 8.8.8.8 pings and fw0's own pings to the
    gateway.
    - With `.10`: 101/125 host 1.1.1.1 (19% loss), and fw0's gateway ping
      from `.10` 99/125.
    - With `.42`: fw0's gateway ping from `.42` 190/190 and from 172.16.80.10
      190/190. Over the same seconds, the LAN host SNATed to the stale `.10`
      reached 1.1.1.1 only 130/190 times, so `.42` against `.10` is a
      same-moment twin.
  - With `.42` as the only v4 address, sessions showed SNAT to `.42`, and
    every probe was 284/284 for 6 min, 1.1.1.1 and 8.8.8.8 included. The
    stale `.10` that #18573 leaves behind had been removed by hand. Back on
    `.10`, the same probes lost 16% again.
  - It is not a cross-cluster ARP conflict: in a simultaneous capture on all
    six loss/tcp/udp WAN members, no xpf MAC ever claimed another cluster's
    address. udp's foreign device broadcast its claim about every 6 s
    (tcp's, about once a minute). udp IPv4 from the LAN host was 11/61,
    with fw0's own ping to the gateway from `.11` 12/61, and from
    172.16.80.11 61/61. IPv6 was 61/61. Only loss's `.8` is unique, and
    loss passes these cells.

  The tcp and udp WAN addresses moved to `.42` and `.43` in the repo. Three
  checks keep this from recurring:
  - `TestSharedSegmentForeignClaims18558` (`pkg/configstore`) refuses a
    shipped claim on any address in the measured foreign list.
  - `test-failover` runs `ha_wan_claim_check` whenever an external IPv4 cell
    fails, and turns that FAIL into a VOID naming the foreign MAC.
    - Only a **non-xpf** claimant does that.
    - A claim by another xpf cluster's RETH MAC (`02:bf:72:<other id>:`) is
      an xpf defect, such as a stale VIP (#18573), so the FAIL stands with
      the other cluster id named.
    - This cluster's own RETH and physical MACs, from both nodes, are own.
    - The cluster id is cross-checked against the live RETH MAC; drift is
      VOID.
    - A PASS is never converted, and a blind probe leaves the FAIL standing.
  - `test-connectivity` runs a preflight cell, "WAN IPv4 ... answered for
    only by this cluster", which FAILs on either kind of claimant, naming
    it.

  If any of the three fires, re-probe and renumber. Never excuse an external
  IPv4 cell without that evidence. The live renumber has a coexistence window
  and a manual step (#18573). Follow the procedure in
  `docs/incus-tcp-udp-plan.md` §3.3, "Renumbering a stack on the shared
  segment". Delete this row once #18575 is merged and both clusters are
  renumbered live.
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
- **COST** (row H11) is a correct move whose transition cost was over budget
  (#18559). It is neither a FAIL nor a clean pass: count it and compare
  against master, like H10's numbers.
- A stream that survives the takeover but dies later is still a death. Check
  the per-stream last-good second. Many streams stopping in the same second
  points at an event (a delete, a reap or a role change), not at load.
