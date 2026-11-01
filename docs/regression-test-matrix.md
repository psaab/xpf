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
| B4a | `make instructions-census` and `make mirror-census` when the diff touches a doc, skill, harness or env file | green | a temporary instruction that outlived its premise (a past `Review-by` date in a touched file, a malformed or misplaced marker) and a mirrored paragraph that drifted from its copies or lost a copy (#18645) |
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
`IPERF_TARGET4/6` (loss `172.16.80.202`, tcp `172.16.80.210`, udp
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
| F3 | **Session-state health.** During a 20 s `-P8` run, check that the serving worker's rows are Established. Today: profile the hot worker (`perf record --call-graph lbr`); `cache_hit_handshake_progress`, `node_served_evidence` and `probe_record_with_origin` must be **absent**, and `SessionKey` hashing should stay well below 10% of cycles | evidence-scan symbols absent | **cross-worker handshakes never completing** (#18520). Flows sat on the 20 s opening window, and every packet paid an evidence scan worth about 40% of worker cycles. The CLI `Timeout` column reads the shared view, which lags the worker tables (#18530), so it is not this row's oracle until #18530 is fixed <!-- Expires-when: #18530 closed --> |
| F4 | Profile the hot worker under `-P8` (`perf record --call-graph lbr -p <helper pid>`) and keep the top 25 symbols with the run | no new top-10 symbol without an explanation | per-packet cost creep. Loss `SessionKey::hash` was 3.3% on 2026-10-19, 16.9% on 2026-10-29, 9.8% after #18520 |
| F5 | New flows during a split (WAN RG on one node, LAN RG on the other), v4 and v6, to the WAN target **and** via a non-default static | 0% loss | split nodes dropping new WAN flows (#18517), stamped fabric punts dropping as Invalid (#18518), a non-default static ending in NoRoute (#18517 review) |
| F6 | **Stalls.** The same `make perf-matrix` run | `RESULT: PASS`: no run errors, no 1 s interval under 25% of the run's peak (healthy runs never dip below 74%), no stream under 1 Mbit/s in any interval | **"the iperfs stop"**: a single stream dying while the others absorb its share keeps the aggregate healthy, so only a per-stream, per-interval check sees it. `make perf-matrix-lib` pins the verdict on fixtures |
| F7 | **Traceroute through the cluster.** From `$CLUSTER_LAN_HOST` (loss: `cluster-userspace-host`): `mtr -n --report --report-cycles=3 -4 1.1.1.1` and `mtr -n --report --report-cycles=3 -6 2001:4860:4860::8888`, then both again with `-u` (UDP probes). **Same-run control:** ping each destination from the same host | if the control ping fails, F7 is VOID and the ping failure is investigated like any F1 failure (upstream or the product; that ping crosses the firewall): never a pass, never an excuse. Otherwise, judged per sub-criterion: **(a)** hop 1 is the LAN-side reth VIP in both families, never a per-node `169.254.x.x` or `fe80::` RETH address; **(b)** hop 2, the first router past the firewall, answers (loss under 100%), which proves upstream Time Exceeded is un-NATed back to the LAN host; **(c)** ICMP mode only, the final hop is the destination at 0% loss. Later intermediate hops may be silent (upstream rate limits), and `-u` is judged on (a) and (b) only, because a public destination need not answer UDP probes | ICMP Time Exceeded from upstream routers not un-NATed back to the LAN host (every hop past the firewall `???` while ping works), and the firewall's own v4 TTL-exceeded sourced from `169.254.2.1` (#18174, user-reported 2026-10-30). On master before #18556, `test-connectivity`'s validators `check_mtr_linklocal4/6` **assert the defect** (they require the 169.254/16 and fe80::/10 first hop); #18556 replaces them with `check_mtr_reth_vip`, which covers (a)–(c) for ICMP mode. No `test-connectivity` cell runs `mtr -u`, so the `-u` half of F7 is always run by hand |

## Tier 3: HA (loss and tcp; destructive targets self-lock)

Clocks: the lab cluster configs carry NTP through `vrf-mgmt` since #18584 (public servers; the incus bridge gateways serve none). A deb deploy preserves node config, so a cluster picks the stanza up only when it is committed on it (see `pkg/cluster/README.md`, "Prerequisite: a cluster needs a time source"). Since #18614 no HA gate sets a node clock. H1, H2 and H3 (`test-failover`, `test-ha-crash`, `test-double-failover`) take one clock reading before the first crash and then, after each crash reboot they wait out (the double-failover's second crash, of fw1, ends that run with fw1 still rebooting, so it has none), run a measured precondition (`failover_clock_cell`, `test/incus/failover-clock-lib.sh`). It waits for the node1−node0 skew, read from this host, plus the reading's own error, to be within 5 s, and for `chronyc tracking` to show a synchronised Leap status (`Normal`, `Insert second` or `Delete second`) on both nodes. It logs the skew, the error and the time it took. The budget is 120 s in `test-ha-crash`. In the other two it is what their iperf timelines already pay for, about 58 s and 88 s after a 22 s comeback, with a 40 s floor. If it does not converge, the cell is scored from the **current** reading (the pre-crash baseline is context in the reason, never a shortcut). **VOID** only where the build cannot be in the path: neither node synchronised and no `system ntp` stanza configured (`cli -c 'show configuration system ntp'`; VOID after one reading), neither synchronised with a stanza whose servers do not answer an SNTP probe from the orchestrator either (a lab NTP outage), or no measurement. **FAIL** otherwise (lab, NTP or product: xpfd owns chrony's `vrf-mgmt` binding and its restart, #18584/#18589): one node synchronised and the other not (the #18584 class: only the RG owner reaching NTP is how fw1 drifted 60–90 s behind in the operator's loop), neither synchronised though the stanza's servers answer the orchestrator, or both synchronised but too far apart. The ledger row carries `clock_converged`, `clock_void` and `clock_resync`, so `ledger_compare --all` tells a clock FAIL (`clock_converged=0 clock_void=0`) from a dataplane FAIL, and a clock VOID turns a would-be PASS row VOID with its reason; a direct run exits 2 on a VOID cell. Since 2026-10-31 all three gate clusters (loss, tcp, udp) carry the stanza and report `Leap status: Normal` on both nodes (tcp's and udp's were committed that day; #18584 closed); the no-stanza VOID now protects only a lab that lacks it. `XPF_FAILOVER_CLOCK_RESYNC=1` is the only way to run these rows on a lab without NTP. It brings back the #11872 `date -u -s` resync and prints a banner, and `harness-result.sh` records the would-be PASS as **VOID** with `clock_resync=1`, so a resynced run can never satisfy H1–H3.
H11 goes further: it has no escape at all. It only reports the skew, because the operator's own loop gets no clock help (`docs/ha-rg-move-correctness.md`).
Before pairing fw0 and fw1 journal times, measure the skew (on 2026-10-30 fw1 ran 66.8 s behind fw0 on loss); a cross-node timeline without that offset produced a wrong diagnosis once.

| ID | Run | Pass | Catches |
|---|---|---|---|
| H1 | `make test-failover` | PASS, including the crash takeover **and** the RG1 failback split, with every stream's last-good second at the end of the run. A "session sync did not become idle" cell is a precondition result, not a takeover verdict (before the RG1 failback it VOIDs RG1 Groups 1–8). Idle = N samples at an unchanged floor, the latest of them included, with no create outstanding beyond that floor and nothing pending at those reads, and no source delta dropped since the wait began; see `docs/userspace-ha-validation.md`, "Session-sync idle precondition" (#18632). **Registered windows (#18617):** the crash `[T, T+3]` is EXCUSED (detection is by design: in the lab about 1.0–1.05 s after the last heartbeat, 0.8–1.05 s after the crash, when the #18570 probe goes unanswered; about 1.2 s more under the sync-recency rule for a peer without ack support). **Per-stream crash and failback cells (#18692):** judged in real seconds on iperf3's clock: the crash anchor is the aggregate's stop inside the orchestrator's sysrq window, mapped through the LAN-host clock offset; the failback anchor is the landing poll's stamp. A stream not resumed within 10 s FAILs. One resumed after 3 s is a COST (a straggler: the 3 s line sits inside the RTO backoff, so it is judged master-relative, with `crash_resume_*` ledger metrics, not gated). Without a clock window the same stop is searched within ±1 s of the integer anchor; with no stop at all the integer verdict is taken at the anchor and ±1 s (no evidence before anchor+1), VOID when those disagree. `cells_cost` also counts planned-move COSTs: `crash_resume_straggler_streams` on the ledger row tells a straggler COST from one. A resuming straggler's zero seconds up to the 10 s line are its COST, not "outside" zeros (`--resume-event-sec`; counted as `crash_resume_excused_zero_intervals`). The harness's own moves are PLANNED and each is one cell: the RG1 split move (anchored at its request and its landing), and the RG0/RG2 failback (both requests, both landings). A move is PASS with no stalled stream (a stall is under 1 Mbit/s for an interval, H11's definition; a stream under 0.05 Gbit/s but not stalled is a low-share transition dip, recorded per move with the move's minimum stream rate and in-window aggregate as `planned_<move>_*` ledger metrics); COST with exactly one stream stalled at most 10 s that recovered (counted as passed and recorded as `cells_cost`, judged master-relative as in H11); FAIL on an all-stream zero interval, two or more stalled streams, a longer stall, or a dead stream. The "per-stream zero intervals outside the crash and planned-move windows" cell (limit 0) counts everything else. The whole-run zero-interval count, which no window excludes, is recorded as `whole_run_zero_intervals` and judged master-relative, not gated, because the crash alone puts every stream at zero. `cells_cost`, `whole_run_zero_intervals` and the `planned_<move>_*` metrics are person-read against master's ledger rows, not automated bands. test-failover has no 10 ms ping, so a stall shorter than one interval goes unscored; H11's ping-gap bound lives only in `test-rg-move-soak` (`docs/userspace-ha-validation.md`). **RG1 Group 1 since #18670** is two judged checks: 1a `Screen drops` (SYN-first drops of non-SYN TCP session misses, limit 4) and 1b a coarse raw `Session misses` floor (limit 256, for misses that resolve to LocalDelivery, which 1a cannot see). The old raw-miss cell had limit 64. Any Group 1–4 delta is VOID when the helper's PID changed inside the window. Ledger rows recorded under the raw-64 cell are not compared with rows recorded since | streams dying on takeover because synced sessions carried truncated zone ids (#18515); the failback split killing established SNAT streams. Three separate mechanisms did that (#18531), and the row only passes when none fire: the LAN node revoked its promoted row against the fabric pseudo-egress and synced the Close to the WAN owner; the WAN owner purged its alias rows as translated-synced when the reply arrived over the fabric link; and the returning owner judged a WAN reply to the SNAT address LocalDelivery and tore the session down at the host-inbound gate |
| H2 | `make test-ha-crash` | PASS on all phases | a stuck restore after a peer restart (#18521 fence and re-prime storm); a lost config-apply ACK blocking RG0 failover (#18521) |
| H2a | **Restore budget**: `test-ha-crash` and `test-restart-connectivity`, the targets that carry `RESTORE_FW0_BUDGET` (#18524) | the post-run restore to node0 takes ≤ `RESTORE_FW0_BUDGET` (default 30 s) with no refused failover. Healthy restores took 9–16 s on 2026-10-29 | a restore that only succeeds on its fourth retry hides a fence or barrier refusal ("demotion peer barrier failed: session sync barrier fenced") that the next real failover hits too (#18523, #18521) |
| H3 | `make test-double-failover` | PASS on both transitions; per-stream data shows every stream resumes after **each** takeover | takeover by a node whose replicas came from a rejoin bulk: on 2026-10-30 the second takeover killed every stream on loss (2 of 4 on tcp) while the first survived |
| H4 | `make test-restart-connectivity` | PASS, no cycle over the loss budget, and the outage does not grow across cycles | daemon-restart blackholes: an orderly private-RG stop handed nothing to the peer and detection was padded by the stopping node's own sync backlog (#18540); an outage that grows cycle over cycle points at state carried between cycles |
| H5 | `make test-active-active` | PASS | split-RG forwarding; a verdict that rejected `secondary-hold` (#18523) |
| H6 | **Split dwell.** Move RG1 to the peer, hold the split ≥ 90 s with `-P8` running, move it back; repeat in the other orientation | 8/8 streams survive both moves | standby replicas reaped at 3 × the opening window (60 s) before they are needed (#18520). H1's failback lands about 64 s after rejoin, right at that edge, so a dwell longer than 60 s is required |
| H7 | **Sync health after every RG move and restart.** Session sync is connected on both nodes within 5 s; a manual failover is admitted within one admission window (no `peer config stale`, no fence refusal); `Sessions stale-config-ignored` does not climb | as stated | a half-open sync connection surviving 56 s (#18521); a fence that never discharges; a config ACK credited then wiped by the peer's new-boot BulkStart (#18521); re-pushes moving the config epoch (#18521 review); the primary ignoring standby epochs (#18526) |
| H8 | **Revocation symmetry.** After H1, compare `show security flow session` on both nodes for the iperf flows | no session row survives on one node whose twin the other node closed | a Close emitted for an alias-only owner keyed on the translated tuple, which left the LAN node's original-tuple row alive and still translating (#18531 review) |
| H9 | **Split-window streams.** In H1's per-stream data, the window where `test-failover` holds RG1 apart from RG0/RG2 (the #11581 isolated-failback slice, 63–73 s) | no stream dies in or after the window; aggregate at or above the split-RG fabric rate, judged separately from the whole-run average. That rate is what flows started on an already-established split reach on the same path. In #18656's same-session control on tcp, fresh flows ran at 16.7 Gbit/s and moved flows at 15.3–15.9 on the fixed build, against 8.6 and 5.8–5.9 on master. `planned_rg1_split_window_aggregate_gbps` was 9.6–10.5 (fixed) against 5.7–6.4 (master) on tcp, and 3.13 against 2.03 on loss. Loss has no same-session fresh baseline (master's fresh run was VOID), so its floor is unset until #18678 re-measures it. The 2.0–3.5 Gbit/s (loss) and about 6 Gbit/s (tcp, RG1-only) figures this row used to cite measured the #18656 slow-path state, not the fabric (`docs/fabric-performance-optimizations.md`). The moves that open and close the window are H1's planned-move cells, `rg1-split` and `rg0-rg2-failback` (PASS, COST or FAIL, never excused). Zeros inside the split, but outside those moves' `[T, T+3]` windows, count in the "outside" cell | streams killed at the split-RG moves (#18531/#18535) read as "slow" because every flow crosses the copy-mode fabric for the whole window; a killed iperf3 scored as 0.0 Gbit/s plus a collapse (#18543). The fabric ceiling itself is #12655 |
| H10 | **Hitless failover** (#18559; generation drops #18560, crash takeover #18561). In one lock cell (`with-cluster.sh`), from `$CLUSTER_LAN_HOST`: `iperf3 -c $IPERF_TARGET4 -p 5211 -P8 -t 120 -i 0.1 -J` and `ping -D -i 0.01 $IPERF_TARGET4`. **Planned:** for each RG in turn, `cli -c "request chassis cluster failover redundancy-group <N> node <taker>"` (an explicit transfer to `<taker>`; without `node` the command demotes the node it runs on, so run on the taker it moves nothing). Confirm with `show chassis cluster status` that the RG moved; a move that did not happen makes the cell VOID. Wait 10 s, then move it back the same way, and finish with `request chassis cluster failover reset redundancy-group <N>` on both nodes. **Crash:** `incus stop --force` the node that owns the data RGs, then restore it. A VM force-stop leaves the survivor's sync socket half-open, so the sync-recency guard is in play; a process kill closes it and is the easier case. Read every timing on the LAN host's clock only (no cross-node pairing) | **Per PR (HA PRs, master-relative):** run each build 3 times on the same cluster. For each number (per-move lost pings, worst stream stall, crash ping gap), the PR's median is at most master's median plus master's own spread (max − min over its 3 runs, and at least 1 ping or 100 ms), and no stream dies. Master's 3 runs are recorded once per merge wave per cluster, by the first HA PR gated there, and reused until the next wave. Single runs spread too far to compare: the same build's worst stall was 1.0 s in one planned run and 1.9 s in another, and before #18570 crash declaration varied by design between the 1.0 s threshold and the 2 s sync window. **Target (#18559; tracked until met):** per single-RG move at most 3 pings lost (30 ms), and no stream has two or more consecutive 100 ms intervals under 1 Mbit/s. A stall of 300 ms or more always fails; one of 200–300 ms fails depending on how it aligns with the intervals, so a single minimum TCP retransmit timeout (about 200–230 ms) usually passes. `-i 0.1` is iperf3's finest interval, so this is the resolution the row has. Crash: the LAN host's longest ping gap is at most 1.4 s, and no stream dies. That bound assumes the 1.0 s staleness threshold of the lab's 200 ms × 5 heartbeat, plus one check tick (50 ms since #18639, 200 ms before), plus activation in what remains. The measured activation, 0.34–0.44 s from peer-lost to the first ping reply (`docs/log/18561.md`), already uses up the 150 ms the shorter tick freed; the threshold counts from the last heartbeat while the ping gap starts at the crash. It also assumes #18570's liveness probe stops the sync-recency guard (`maxPeerSyncSilence`, 2 s) from deferring declaration on a half-open socket, which holds for a peer that has acked a sync-level heartbeat and has no pre-crash frame handled after the probe; for a peer without ack support the guard can still push it past 2 s | baseline on loss, 2026-10-30, master `2cf76b8d92` plus #18556 (build `848d475531`): three sequential single-RG moves (RG0, RG1, RG2) lost 23 pings in all (failback 26), with the largest single gap 9 pings; a batch move of all RGs lost 20–21; and the worst single-stream stall per run was 1.0, 1.3 and 1.9 s (TCP backoff after short losses). A crash of the owner left a 2.2 s ping gap (one run). Sessions are already on both nodes, so every lost packet is a transition defect: the demote/activate gap, drops on the old owner, generation-stamp drops at each helper publish, the split window between per-RG moves. Scripted versions of both procedures land with #18559 |
| H11 | **One-node RG-move soak** (#18583): `make test-rg-move-soak` (ledger-wrapped, smoke-cells). Issues `request chassis cluster failover redundancy-group <rg> node 0|1` from ONE node, alternating, `SOAK_SLEEP` s after each CLI return, under IPv4+IPv6 `iperf3` and `ping -D -i 0.01` from `$CLUSTER_LAN_HOST`, and NEVER fixes clocks (the preflight reports node1−node0 skew). Per HA PR: `SOAK_MOVES=40 SOAK_SLEEP=5` from node0, then `SOAK_MOVES=40 SOAK_SLEEP=2 SOAK_FROM=1`, PR and master in the same window on the same cluster. Per merge wave on loss: `SOAK_MOVES=200` at `SOAK_SLEEP=5` and at `SOAK_SLEEP=2` | **Correctness (absolute):** no FAIL and no VOID move, and not a void run. A move is correct when the CLI says `transfer committed`; both nodes' own views show the target primary and the other node `secondary`/`secondary-hold` within `SOAK_CONVERGE_S` of the CLI returning and for the rest of the window (no dual-active sample, no revert); each node's `Forwarding: rg-active=` line and each helper's `ha_groups[].forwarding_active` (active and an unexpired lease) agree; the traffic followed (the target's RETH-member counters carry the packets and the LAN host's neighbour entry resolves to the target's MAC); traffic flows in the window's tail; and no stream dies. **Transition cost (master-relative, as H10):** a single-stream stall over 2000 ms that recovers within 10 s, with ping gaps ≤ 1000 ms and no all-stream outage over 1000 ms, scores COST, not FAIL (#18559); more than one stream stalling, or a wider gap or outage, is a FAIL. The ledger row carries `cells_cost` (recorded; `ledger_compare` compares only the headline, so this comparison is made by hand). Per PR, the PR's COST count and median/p95 worst-stall are at most master's plus master's own spread over the same number of runs, and no new FAIL class appears | the operator's pattern, which no other row runs: on 2026-10-31 loss had fw1 72 s behind with no NTP, and every move to node1 failed fabric auth (`window 60s/90s ahead of ours`) while every move back printed `already primary`. That was 10 FAIL and 10 VOID in 20 moves, and traffic never left node0. The NTP fix is #18584 and peer-skew visibility #18585. With both, on loss (0.0.26140): 200 moves at 5 s all landed, with 5 single-stream stalls of 2.2–6.6 s (COST under today's rule); 200 at 2 s all clean. tcp (30) and udp (40, every RG from node1 at 2 s) all landed. Split-RG moves of RG2 alone run every flow over the fabric while RG2 is away (loss tail about 2.7 against 11.5 Gbit/s), which is expected |

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
  <!-- Expires-when: #18559 closed -->
- **H10 hitless targets: #18559** (with #18560 and #18561). The row's
  baseline (master plus #18556) misses the targets, so HA PRs are gated on H10's
  master-relative numbers until #18559 closes.
  <!-- Expires-when: #18559 closed -->
- **MTR / traceroute cells: #18174, fixed by #18556.** Every cluster MTR
  cell in `test-connectivity`: "mtr LAN→WAN gateway (via RETH link-local)",
  "mtr LAN→internet IPv4 (via RETH link-local)", "mtr LAN→internet IPv6
  (via RETH link-local)", and Group11 IPv4/IPv6 MTR. Two of them were excused
  here as an upstream issue. #18556 (merged 2026-10-31) landed the hop-1
  fix together with its validator, which now expects the RETH VIP as hop
  1 ("first hop ... is not the RETH VIP"); the validators before it
  rejected the correct VIP first hop as "not an IPv4 link-local RETH
  address". Ping to a live destination
  (`1.1.1.1`, `2001:4860:4860::8888`) works in both families while every
  hop past the firewall is `???`. They are row F7.
  <!-- Expires-when: #18174 closed -->
- **Fabric/control host pings: #18212.** Pings fw0↔fw1 on 10.99.x fail on
  loss, tcp and udp. Host ICMP to the WAN gateway (`172.16.50.1`) failed
  on tcp (integ9, integ10) and on udp, and passed on loss (integ8–10). That
  WAN-gateway leg was #18558, not #18212: tcp's and udp's WAN addresses were
  duplicates on the lab segment, and loss's `.8` is not. Since the live
  renumber of 2026-10-31 it is expected green on all three clusters (see the
  environment row below). The 10.99.x fabric/control pings remain #18212.
  <!-- Expires-when: #18212 closed -->

## Known environment rows (re-verify before excusing)

Before excusing a cell here, run a control in the same run that takes the
product out of the path, for example the same destination from the incus
host or the orchestrator. If the control passes, the cell is a product
failure.

- **Duplicate WAN address on the shared VLAN 50 (#18558).** Resolved
  2026-10-31: tcp and udp were renumbered live to `172.16.50.42` and `.43`
  (#18575; `docs/incus-tcp-udp-plan.md` §3.3). Their old `.10`/`.11` are
  held by non-xpf lab devices; loss's `.8` is unique. No cell is excused by
  this row today. It is kept as a recurrence rule instead of being deleted,
  so the excuse for a repeat comes with its control.
  - **In scope:** the external IPv4 cells (1.1.1.1, 8.8.8.8) and the
    firewall's own WAN-gateway ping, on tcp, udp or loss.
  - **When the FAIL is environment:** only while `ha_wan_claim_check`
    returns status 1 (a non-xpf claimant) for that cluster's WAN address in
    the same run. A ping from the orchestrator cannot stand in, because it
    does not leave from the duplicated address.
  - **Other statuses:** status 3 (another xpf cluster's RETH MAC) is a
    product failure. Status 2 (not measured) leaves the FAIL standing.
  - **If the check fires:** re-probe and renumber, following the plan's
    §3.3 procedure.
  - **References:** the guards (`TestSharedSegmentForeignClaims18558`,
    test-failover's claim-gated VOID, and test-connectivity's "WAN IPv4 ...
    answered for only by this cluster" cell) and the evidence are in
    `docs/log/18558.md`.
- **loss's v4/v6 iperf targets are different hosts (#18576, #18586).**
  loss's v4 `172.16.80.202` is the xpf-mouse-target container
  (`10:66:6a:8b:91:a4`) and `2001:559:8585:80::200` is the external v6 box
  (`f6:f0:06:10:77:d5`), so the Group12 neighbor identity cannot require one
  MAC there. `test/incus/loss-userspace-cluster.env` sets
  `IPERF_TARGET_V4_V6_SAME_HOST=no` with
  `IPERF_TARGET6_SPLIT_HOLDER=f6:f0:06:10:77:d5`.
  - **Control (same run):** the cell's own read on the RG owner. The waiver
    holds only while v6 names the declared holder and v4 names a different
    MAC. Either check failing is a VOID, never a PASS.
  - **Delete when:** loss's v4 and v6 targets are one host (or the v6 box
    is renumbered). Remove both env lines; the same-host identity check then
    applies.
    <!-- Expires-when: loss's v4 and v6 iperf targets are one host; Review-by: 2026-11-30 -->
- **tcp and udp host SR-IOV VFs.** Two host faults have each left a
  force-stopped firewall VM unable to restart or forward. This is
  environment only while the host check below shows the fault in the same
  run. A firewall cell that fails with a clean host check is a product
  failure.
  - **VFs claimed by the host network.** The host's dracut default network
    must not manage the VF netdevs. Without that, a force-stopped VM cannot
    restart: "All virtual functions on parent device mlx1 are already in
    use".
    - **Check:** `ssh tcp` / `ssh udp` (the host aliases `docs/incus-tcp-udp-plan.md` uses), then
      `ip -br link | grep -E '^eno[12]v' | grep -c UP` must be 0 for free
      VFs.
    - **Fix:** write
      `/etc/systemd/network/05-xpf-sriov-vf-unmanaged.network` containing
      `[Match]` `Name=eno1v* eno2v*` and `[Link]` `Unmanaged=yes`, run
      `networkctl reload`, then `ip link set <vf> down` for each free VF
      that is UP.
    - **Applied:** tcp's host 2026-10-29, udp's 2026-10-31 (UTC).
  - **A stale host port VLAN on a reassigned WAN VF.** incus records a VF's
    state before attaching it (`volatile.wan-vf.last_state.vf.vlan`) and
    restores it on stop. On incus 7.0.1 (the tcp and udp hosts), a
    `wan-vf` device that sets no `vlan` leaves the VF with whatever VLAN it
    last carried. Incus 7.6.0 and later clear it on start (upstream
    473c98eb2cc9). On 2026-10-31 00:39 UTC udp fw0's WAN VF
    (`mlx0 vf 0`) came back on port VLAN 80. Its tagged `reth0.50`/`.80`
    frames died, and neighbour entries went FAILED in both families after
    every restart.
    - **Check:** find the VF with
      `incus config get udp:xpf-udp-fw0 volatile.wan-vf.last_state.vf.id`
      (WAN VFs are all on `mlx0`), then `ssh udp 'ip link show mlx0'`. That
      VF must show no `vlan`. The target VF on `mlx0` carries access
      `vlan 80` by design.
    - **Repair:** run `sudo ip link set mlx0 vf <id> vlan 0` on the host,
      plus `incus config set <remote>:<vm> volatile.wan-vf.last_state.vf.vlan=0`
      so that the restore on stop writes 0.
    - **Not durable:** VF allocation is not pinned, so a different VF can
      bring the fault back. This out-of-band repair is the sanctioned
      exception to the plan's "never set VF VLAN by hand" rule until #18582
      makes WAN VFs clear their VLAN on start. Two durable options are
      `vlan: "0"` on the device, which 7.0.1 accepts, or upgrading incus to
      7.6.0 or later.
      <!-- Expires-when: #18582 closed -->

## Reading results

- **FAIL** is attributable: the binary was confirmed to be the build under
  test.
- **VOID** means the measurement cannot be attributed (`exe_check` mismatch,
  a precondition, a harness fault). Fix the cause and rerun; a VOID is never a
  pass and never a regression.
- **F1's "iperf target ... answered for by exactly one host" cell
  (#18578, #18576)** checks that the v4 iperf target is held by one host.
  It probes from the cluster's target container (`MOUSE_TARGET_REF`),
  never from a firewall node: probing from the RG owner re-ran the
  neighbor race on it. It sends three RFC 5227 rounds (sender 0.0.0.0, so
  no cache learns from them) for `IPERF_TARGET4`, with the cluster's own
  `WAN_GW80_4` as the positive control. On the firewalls it only reads
  both nodes' neighbor entries, before and after the probe.
  - **PASS:** the container alone holds the target, and the RG owner's
    entry is absent or names the container.
  - **FAIL:** any second holder (no env has an excuse set since
    `IPERF_TARGET4_KNOWN_HOLDERS` was deleted), or an xpf RETH MAC
    holder. On the RG owner only, it is also a FAIL when the entry is
    FAILED, names a MAC nobody claims, or changes between the snapshots.
  - **VOID:** the control did not answer; nobody, or only another host,
    holds the target; the owner's entry (even STALE) names another MAC;
    there is no single stable RG owner.
  - **Why it exists.** Until 2026-10-31 loss targeted `172.16.80.200`.
    The external v6 box (`f6:f0:06:10:77:d5`), which is in no incus
    instance and has no SSH handle, also answers ARP for it. In a loss
    `test-rg-move-soak` that day, fw1 resolved `.200` to that box: all 8
    v4 iperf streams died while v4 ping kept answering from the wrong
    host, and all 20 moves FAILed on environment. loss now targets
    `172.16.80.202`. `mouse-addr.service` pins it on the container
    (`TARGET_ALIAS_V4`, derived from the env), and it was claim-probed
    unique before use. It is not `.201`, the separate #8259 mouse
    address, and not `.174`, the container's DHCPv4 lease, which nothing
    pins. Whether `.202` lies outside the lab DHCP server's pool is not
    shown; this cell bounds that risk in every run. Harnesses that still
    hard-code `.200` are listed in `docs/log/18576.md`.
  - **The deprecated `.200`.** `.200` stays pinned on the container as a
    DEPRECATED alias (`TARGET_ALIAS_V4_DEPRECATED` in the loss env), so
    a container restart does not strand those harnesses and older
    checkouts. `mouse-target-setup.sh` keeps it only while it is held,
    and never claims it anew. It is still dual-held, so nothing may
    measure it, and this cell never probes it. **Expiry** (tracked on
    #18576): once the hard-coded follow-ups are retargeted and no open
    branch predates #18619, delete the env line, then run
    `ip addr del 172.16.80.200/24 dev eth0` on the container.
    <!-- Expires-when: #18576 closed -->
  - **`mouse-target-setup.sh up`** probes each NEW v4 address from the
    container before it writes the unit, and refuses if another MAC
    answers or the control is silent. It runs under the cluster lock.
  - **When a loss iperf3 run stops or slows**, start `ip monitor neigh`
    on both nodes before the rerun (node0 on `ge-0-0-2.80`, node1 on
    `ge-7-0-2.80`). After it, read
    `ip -s neigh show "$IPERF_TARGET4" dev <that interface>`. A move to
    another MAC is environment only if this cell shows a second holder
    in the same run. Otherwise it is a product neighbor fault.
- **F1's "Group12 read-only neighbor identity" cell (#18586)** reads the RG
  owner's neighbor entries for the WAN iperf targets: the one node holding
  `WAN_GW80_4` (exact address match), on the device its route to each target
  names. It used to read the LAN host, which never holds an entry for an
  off-subnet target, so it was VOID on every run, and with it the whole
  `test-connectivity` run. The owner is read before and after the neighbor
  reads; the cell is read-only (`ip route get`, `ip neigh show`).
  - **Usable entry:** one line, on the route's device, with an `lladdr` and
    one of the NUD states REACHABLE, STALE, DELAY, PROBE or PERMANENT.
  - **FAIL:** either family's entry is FAILED, INCOMPLETE, NOARP or NONE,
    or names a device other than its route's. Where the v4 and v6 targets
    are one host (`IPERF_TARGET_V4_V6_SAME_HOST=yes`, the default; tcp,
    udp), it is also a FAIL when the two routes or the two entries name
    different devices, or the two entries name different MACs.
  - **VOID:**
    - `IPERF_TARGET_V4_V6_SAME_HOST` is neither `yes` nor `no`;
    - no single node holds `WAN_GW80_4`, or a node's addresses cannot be
      read;
    - the owner changed between the reads;
    - the owner has no route device for a target, or the route goes `via`
      a gateway (not on-link);
    - an entry is missing, has more than one line, or has no single NUD
      state or no MAC;
    - in split mode (`no`), `IPERF_TARGET6_SPLIT_HOLDER` is unset, the v6
      entry names another MAC (the waiver is stale), or the v4 entry names
      the v6 holder (that run's v4 iperf numbers measured the wrong host;
      record it on #18576).
  - **Split-mode PASS** says "identity not asserted": each family is
    usable, v6 is the declared holder and v4 is a different host. It is
    loss's waiver row under "Known environment rows", not an identity
    proof.
- **SKIP** is either a cell that did not run, or an environment row's
  excused state. The ledger's `cells_skipped` counts both. The excused kind
  carries its marker in the cell text (no env emits one today: "EXCUSED
  #18576" ended when loss's v4 target moved to `.202`), and it is neither a
  pass nor a failure. A SKIP without a marker means the cell did not run.
- **COST** (row H11) is a correct move whose transition cost was over budget
  (#18559). It is neither a FAIL nor a clean pass: count it and compare
  against master, like H10's numbers.
- A stream that survives the takeover but dies later is still a death. Check
  the per-stream last-good second. Many streams stopping in the same second
  points at an event (a delete, a reap or a role change), not at load.
