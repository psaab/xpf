# Correct redundancy-group moves

What a correct operator-driven redundancy-group (RG) move is, which code path
each form of the command takes, what it depends on, what traffic must do, and
how to test it the way an operator runs it (#18583, regression matrix row
H11).

## Why this document exists

An operator moving RG2 back and forth runs something like this, from one
node, with no clock help:

```sh
for n in $(seq 10000); do
        incus exec xpf-userspace-fw0 -- cli -c \
            "request chassis cluster failover redundancy-group 2 node $[n%2]"
        sleep 5
done
```

On the loss cluster on 2026-10-31 every `node 1` iteration printed:

```
error: rpc error: code = Unavailable desc = cannot connect to peer on any
fabric address: rpc error: code = Unauthenticated desc = fabric RPC
authentication failed: invalid auth token (the token authenticates under an
accepted key at a window 60s ahead of ours, so the PSK is correct; ...
Synchronise NTP on both nodes)
```

and every `node 0` iteration printed
`Redundancy group 2 is already primary on node 0`. RG2 never left node0 and
traffic never reached node1, although the loop looked busy.

Every HA gate before H11 missed this, for two reasons. The gates and the
measurement scripts set both node clocks from the orchestrator before they run
(`failover_resync_node_clocks`, #11872, and the hitless experiment scripts).
And they do a few moves and then restore, instead of one node issuing
alternating moves indefinitely. Since #18614 the crash gates no longer set a
clock: they wait for NTP and fail when it does not converge (see "Crash gates:
NTP convergence is a measured precondition" below).

## What a correct move is

A move of RG *g* to node *t* is correct when all of these hold:

1. **The command tells the truth.** It reports
   `Manual failover completed for redundancy group g (transfer committed)` and
   the RG did move. "Already primary" is correct only when node *t* already
   owned *g*.
2. **Exactly one owner before and after, in both nodes' own views.**
   - node *t*'s `show chassis cluster status` shows itself `primary` for *g*;
   - the other node's own view shows itself `secondary` or `secondary-hold`
     (a local untargeted resign parks the old owner in `secondary-hold`; on
     the owner of a data RG with a live peer the untargeted form runs the
     targeted transfer since #18559, and the old owner ends `secondary`).
   - One node's view is not enough. node0's view alone scores a dual-primary
     split as healthy (the #18503 rule).
3. **Forwarding follows ownership.** Each node prints its own
   `Forwarding: rg-active=<active|inactive>` line under its own row (the
   daemon's *applied* RG state, #7367/#8326). The owner reads `active`, the
   other node `inactive`, and neither line carries a ` -- DIVERGENCE` suffix.
4. **The helper agrees.** Each node's userspace-dp helper reports
   `ha_groups[].forwarding_active` true on *t* and false on the other node.
   That is what the helper forwards on (`active` AND an unexpired lease), so
   an RG marked active with an expired lease does not pass.
5. **No dual-active sample**, at any point during the move: no sample in
   which both nodes claim the RG, or both forward it. During a move the soak
   reads the commanded target first and the old owner second, so a clean
   handoff cannot be read as dual-active. Every dual-active sample FAILs
   (#19041; see "Sampling both nodes" below).
6. **Traffic follows.** Sessions are already on both nodes (session sync), so
   established flows keep running through the new owner:
   - ping loss and the longest ping gap stay within budget;
   - no iperf3 stream stalls past budget, and none dies;
   - traffic is flowing again in the tail of the move's window.
7. **Within the operator's cadence.** The RG has landed before the operator's
   next command, which their loop issues `sleep S` after this one returns.

The direction does not matter, and neither does which node issues the
command. node0→node1 and node1→node0 must both be correct whether the command
runs on the giving node or the taking node.

## The command forms and their code paths

`request chassis cluster failover ...` is parsed once, in
`pkg/clusterfailover`, and handled by the gRPC server
(`pkg/grpcapi/server_diag_system_action.go`) for the remote `cli`, or by
`pkg/cli/cli_request_chassis.go` for the local CLI. The forms are:

| Form, run on node A | Path | Transport | Depends on the wall clock? |
|---|---|---|---|
| `redundancy-group g node A` (target is the local node) | `RequestPeerFailover(g)`: A asks the current owner to transfer *g* out, and A takes it | session-sync connection | no |
| `redundancy-group g node B` (target is the peer) | `proxyClusterFailover`: A proxies the request over fabric gRPC to B, and B then runs `RequestPeerFailover(g)` locally | fabric gRPC (PSK token, 30 s window), then session sync | **yes**: the fabric token |
| `redundancy-group g` (no `node`), A owns data RG *g*, the peer is alive (#18559) | `proxyClusterFailover` of `redundancy-group g node B`: exactly the row above. The command waits for the commit (1.0-1.8 s on loss), and A ends `secondary` with `Manual: no`. If B ACTUALLY answers "already primary" (dual-active) and A is still primary at the epoch it recorded, A resigns locally: `... (the peer is also primary; resigned locally)`; B can yield in between, leaving the RG ownerless for up to one heartbeat (#19029). A proxy deadline reconciled from A's heartbeat view is returned as the row above returns it and never resigns | fabric gRPC, then session sync | **yes**: the fabric token. A #18585 clock refusal, or no fabric address accepting a TCP connection, falls back to the local resign below, with the reply `... (peer unreachable; resigned locally, break-before-make)` |
| `redundancy-group g` (no `node`), every other case: RG0, A not the owner, a dead peer | `ManualFailover(g)`: A yields *g* (A goes to `secondary-hold` with the manual flag set, the peer takes over). Run on the non-owner it moves nothing, but it still parks that node in `secondary-hold` with the manual flag until `failover reset redundancy-group g` | local, then heartbeat/election | no |
| `data node N` | every data RG (ID > 0) not already on N, in one batch. To the local node it uses `RequestPeerFailoverBatch`; to the peer it is proxied like `node B` | as above | as above |
| `reset redundancy-group g` | `ResetFailover(g)`: clears *this* node's manual-failover state for *g* and resumes normal election for it (not the node-wide kernel-upgrade hold) | local | no |

Things that follow from this table:

- **Half of the operator's loop crosses the fabric.** Issued from node0,
  every move to node1 is a fabric RPC and every move back to node0 is a local
  pull. A loop issued from node1 has the same shape the other way round.
- **"Already primary" is computed locally.** On the local-target path the
  handler answers "already primary" from `IsLocalPrimary(g)` without contacting
  the peer. After a failed move to the peer, the next move back to the local
  node prints it, which is correct but easy to read as "the move worked".
- **To get round a broken fabric path, run the command on the target node.**
  `request chassis cluster failover redundancy-group 2 node 1`, run on node1,
  needs no fabric RPC. It is a workaround, not the fix.

## The clock dependency

The fabric gRPC token is `HMAC(PSK, method, request digest, unix_time / 30)`.
The verifier accepts the current window and one on each side
(`pkg/grpcapi/fabric_auth.go`). Between the two nodes' wall clocks:

| Skew | Cross-node fabric RPC |
|---|---|
| under 30 s | always accepted |
| 30–60 s | accepted or rejected, depending on where each clock sits in its window |
| 60 s or more | always rejected (`clockskew.AuthBreakSkewSecs`) |

The accept band is the replay horizon for captured tokens, which include
`ClearSessions` and cross-node failover. That is why it was not widened
(#6708, #7487). The fix for skew is time synchronisation, not a wider band.

Heartbeats, election, session sync and the local-target move do not depend on
the wall clock at these skews. (The keyed heartbeat's boot epoch is a
wall-clock value with a one-hour plausibility bound, `bootEpochMaxSkew`, so a
skew past an hour does reach heartbeat admission —
`pkg/cluster/heartbeat_epoch_admit.go`.) That is why a skewed cluster looks
healthy in `show chassis cluster status` while every cross-node RPC fails.

### Why the lab drifted

- `chrony` runs on every node, but with no reachable source. On 2026-10-31
  both loss nodes reported `Reference ID 00000000` and
  `Leap status: Not synchronised`, and `chronyc sources` was empty.
  `timedatectl` still printed `NTPSynchronized=yes`. xpf's clock monitor
  (`pkg/clockskew`) reads `chronyc tracking` first and uses `timedatectl` only
  as a fallback when chronyc is unavailable, so it was not misled.
- The only off-box route a cluster node is guaranteed to have is in the
  management VRF (`vrf-mgmt`, table 999, the fxp0 DHCP default). The default
  instance's default route leaves through the WAN RETH, which only the node
  that owns that RG has; the other node has a `blackhole default`. chronyd in
  the default instance therefore reaches a public server on one node at most,
  and a failover moves that reachability to the other node.
- Crash-reboot HA tests re-read a guest RTC that was already behind. On fw1,
  `rtc_cmos: setting system clock` at boot was about 71 s behind real time,
  and nothing corrected it. The drift itself was small (13.6 ppm).
- The incus host bridge gateways (10.136.126.1, .127.1 and .128.1) do not
  answer NTP. Public servers are reachable through `vrf-mgmt`:
  `chronyd -Q 'server 162.159.200.1 iburst'` times out on a secondary node,
  and the same query with `bindacqdevice vrf-mgmt` succeeds.

### What makes it correct

- Configure NTP on both nodes, reached through the management VRF:
  `set system ntp server <address> routing-instance mgmt`. Since #18584
  (merged as 4546218cc3; on a build without it the routing-instance is
  advisory only and chrony stays in the default instance), xpf renders
  this as chrony `bindacqdevice vrf-mgmt`
  (`/etc/chrony/conf.d/xpf-acquisition.conf`), for `mgmt` only when a
  management interface exists. chrony has one acquisition device, so every
  server must name the same instance; mixed instances commit with an
  advisory and nothing is bound. A cluster whose servers use the default
  instance gets a commit advisory naming the secondary node. #18584 also adds
  the stanza to the lab cluster configs; a deb deploy keeps node config, so
  commit it on a running cluster (`pkg/cluster/README.md`).
- Boot from a lagging RTC. The distro `chrony.conf` (kept by
  `scripts/image/bake.py`) carries `makestep 1 3`, so the first three clock
  updates after chronyd starts are stepped. xpfd restarts chrony once per
  daemon process after it first renders the binding. That covers a chronyd
  that started before `vrf-mgmt` existed, and it re-opens the step window.
  Measured on tcp fw1 (a secondary):
  `System clock was stepped by 1.103495 seconds` about 8 s after the restart.
- Visibility before the break. With #18585 (also an open PR when this was
  written) the nodes compare their wall clocks over the authenticated
  heartbeat: `show chassis cluster status` prints `Peer clock offset`, an
  alarm raises at 10 s (also to syslog), and `failover ... node <peer>`
  refuses at 60 s with `cross-node request not sent: ...` naming the skew
  and the remedy. Without it, `show chassis cluster status` carries only the
  post-break #6708 skew line, plus the local reference alarm
  (`pkg/clockskew`).

How to check a node:

```sh
incus exec <node> -- chronyc -n tracking | grep -E 'Reference|Leap|System time'
incus exec <node> -- chronyc -n sources
incus exec <node> -- cli -c 'show chassis cluster status' | grep -A3 Warning
```

### Crash gates: NTP convergence is a measured precondition (#18614)

A crash-rebooted node starts from its RTC and stays at that offset until
chrony steps or slews it. An operator's cluster lives in that state, so
`test-failover`, `test-ha-crash` and `test-double-failover` (rows H1–H3) no
longer repair it. They use `test/incus/failover-clock-lib.sh`:

- `failover_clock_baseline`: one reading before the first crash, plus the
  `system ntp` config. It is recorded as context for a later verdict's reason,
  never as a decision. A single instant can catch a chrony blip, and a
  one-node-synchronised baseline is the #18584 state the gate exists to catch.
- `failover_clock_reading`: a measure-only reading right after a
  crash-rebooted node is back (in `test-ha-crash`, before its 10 s settle),
  so a later rejoin FAIL has the post-crash clock state in its log.
- `failover_clock_cell` (around `failover_clock_precondition`): after each
  crash reboot the harness waits out, before the failback or the next crash.

The precondition reads both nodes from the orchestrator until two things
hold:

- `|skew| + error <= 5 s`. Each node's offset against this host is the
  midpoint of the minimum-RTT sample of three `incus exec date` samples (the
  soak preflight's method), so the host clock cancels. The error is half the
  two chosen samples' RTTs, about 0.2 s on loss. A reading whose error alone
  is over 1 s (`XPF_FAILOVER_CLOCK_MAX_UNC_S`) is too noisy to count.
- `chronyc -n tracking` shows a synchronised Leap status on **both** nodes:
  `Normal`, or `Insert second` / `Delete second` around a leap second.

It reads again every 2 s, up to the budget. It logs the first reading (the
post-crash state), each change, and the result with the time it took and
both nodes' uptimes:

```
clock precondition [phase1]: 1.8 s: waiting: node1-node0 skew -1.063 s (+/-0.199 s); chrony loss:xpf-userspace-fw0: Not synchronised [00000000 ()], loss:xpf-userspace-fw1: Normal [A29FC801 (162.159.200.1)] (bound 5 s, budget 120 s)
clock precondition [phase1]: converged 5.6 s after the check began (up loss:xpf-userspace-fw0 29 s, loss:xpf-userspace-fw1 18523 s): node1-node0 skew -1.110 s (+/-0.203 s); chrony loss:xpf-userspace-fw0: Normal [A29FC87B (162.159.200.123)], loss:xpf-userspace-fw1: Normal [A29FC801 (162.159.200.1)] (bound 5 s)
CLOCK_PRECONDITION: resync=0 converged=1 verdict=PASS skew_s=-1.110 converge_s=5.6 bound_s=5 budget_s=120 label=phase1
```

If it does not converge, the cell is scored from the **current** reading. The
precondition reads `cli -c 'show configuration system ntp'` from the
un-rebooted peer; whether the stanza exists is a config fact the build cannot
influence.

| State at the end | Verdict | Reads as |
|---|---|---|
| neither node synchronised, no `system ntp` stanza (decided after one reading; no budget spent) | VOID | no time source (lab) |
| neither node synchronised, stanza configured, and none of its servers answers an SNTP query from the orchestrator either | VOID | lab NTP outage (the off-path control) |
| a clock unreadable, the reading too noisy, or the ntp config unreadable | VOID | no measurement (harness/lab) |
| ONE node synchronised and the other not (either node, with or without a stanza) | FAIL | #18584 class: only one node reaching NTP is how fw1 drifted 60–90 s behind in the operator's loop |
| neither node synchronised, stanza configured, and its servers answer the orchestrator (or the probe is unavailable) | FAIL | lab, NTP or product |
| both synchronised, further apart than the bound | FAIL | lab, NTP or product |

Every FAIL is attributable because xpfd owns chrony's `vrf-mgmt` binding and
its restart (`pkg/daemon/daemon_system.go`, #18584/#18589): a build that breaks
them fails here, and the reason names the skew, both chrony states, the
stanza, the probe result and the pre-crash baseline. A VOID prints a
`CLOCK_VOID:` line; `harness-result.sh` turns a would-be PASS row VOID with
that reason, and a direct run of any of the three smokes exits 2. Every row
with a precondition carries `clock_converged`, `clock_void` and
`clock_resync`, so `ledger_compare --all` tells a clock FAIL
(`clock_converged=0 clock_void=0`) from a dataplane FAIL.

Where each harness runs it, and its budget:

- `test-ha-crash` runs it after the rejoin and dual-active checks, just before
  the failback, in phase 1 and every phase 3 cycle, and after any node the
  final health check had to start. Those checks keep their 10 s settle and see
  the cluster in its real post-crash clock state; only the failback waits. The
  budget is 120 s. The cell is FAIL-only (a resync still gets a PASS line
  naming it, and a VOID a VOID line), so a converged run has the same cell
  count as before (44).
- `test-failover` and `test-double-failover` run it right after xpfd is back.
  Their 20 s settle counts from xpfd coming back, so the post-crash checks
  start no later than before when NTP converges inside it. Their budget is the time those timelines
  already pay for: the part of `REBOOT_WAIT` the comeback did not use, plus
  the 20 s settle. That is about 58 s in `test-failover` and 88 s in
  `test-double-failover` after a 22 s comeback. The floor is 40 s, over twice
  the measured 17–18 s convergence. It only binds after a comeback slower than
  40 s (measured 19–22 s). Its at most 20 s overshoot is paid for:
  `test-failover`'s `IPERF_DURATION_MIN` carries a `CLOCK_FLOOR_OVERSHOOT`
  term (20 s), which makes its whole iperf run 20 s longer. The
  double-failover's fixed 300 s run already outlasts its
  worst case with the floor included (about 220 s summed from its own
  waits). The double-failover's second crash (fw1) ends that
  run while fw1 is still rebooting, so it has no clock cell.

Why these numbers:

- **Bound, 5 s.** It is the #18585 alarm's clear threshold
  (`PeerClockSkewClear`, `pkg/cluster/peer_clock_skew_18585.go`), so a
  converged gate never runs while that alarm is raised. Every wall-clock
  comparison in `pkg/cluster` and `pkg/grpcapi` tolerates 5 s, and fabric
  tokens authenticate under 30 s in any window alignment. The bound must also
  not trip on a converged cluster. On loss with both nodes `Normal`, this
  method read up to 0.23 s while the heartbeat read 0.0 s (RTT 0.18–0.21 s).
  On the #18614 live runs, six crash reboots gave these converged readings:
  −1.07, +0.07, +0.49 and +0.04 s on run 1; −1.11 s on run 2; −1.49 s on
  run 3. The three near −1 s were all phase-1 readings, taken within seconds
  of fw0 turning `Normal`. One of them had both nodes on the same server, so
  the servers' disagreement does not explain them. A 2 s bound would have
  left 0.5 s of margin. With this check's final code, the passing live
  `test-ha-crash` converged at +0.69, +0.01, +0.80 and +0.01 s, with an error
  of +/-0.18 to 0.19 s, and `test-failover` at +0.09 s.
- **Budget, 120 s** (`test-ha-crash`'s default). On run 1 (loss,
  0.0.26315+g960e6397a4e0, four `incus stop --force` reboots of fw0), xpfd was
  active 19–20 s after `incus start`. chrony on fw0 reached `Normal`
  17.2–18.1 s after that. The first readings, about 2 s after xpfd came back,
  were +0.21 to +1.63 s with fw0 `Not synchronised`. Runs 2 and 3, and the
  final passing run (0.0.26620+g960e6397a4e0), check after the rejoin checks.
  There fw0 was `Normal` by uptime 28–31 s. The measure-only readings at
  uptime 14–15 s read +0.78 to +1.45 s, with fw0 still `Not synchronised`. The
  journals of five earlier crash reboots (0.0.26314) show the sequence:
  chronyd started about 8 s after kernel boot, logged `Can't synchronise: no
  selectable sources` at 22–25 s, and selected a source at 26–29 s. None
  logged a step: the RTC came back within chrony's 1 s `makestep` threshold,
  so only the Leap status was outstanding. 120 s is over 6× the measured
  time, and still covers one full 64 s default poll interval if the first
  iburst round runs before vrf-mgmt can route.
- **Overrun.** The budget is checked after each reading, and the last sleep is
  cut to the time left. So a verdict lands at most one reading past the budget,
  about 1.5–2 s on loss (three samples per node plus two `chronyc`). Every node
  command runs under a host-side `timeout`, so a wedged `incus exec` costs at
  most 10–15 s per command.

Knobs: `XPF_FAILOVER_CLOCK_SKEW_BOUND_S`, `XPF_FAILOVER_CLOCK_BUDGET_S` (an
explicit value overrides every harness's own budget),
`XPF_FAILOVER_CLOCK_POLL_S`, `XPF_FAILOVER_CLOCK_SAMPLES` and
`XPF_FAILOVER_CLOCK_MAX_UNC_S`. A malformed knob is refused, and the cell is
VOID.

`XPF_FAILOVER_CLOCK_RESYNC=1` is the escape for a lab with no NTP. It
measures and logs the state and prints a banner saying the run is not
operator-faithful. Then it runs the #11872 `date -u -s` from one host
reading, and the cell gets an explicit PASS line naming the resync.
`harness-result.sh` records the would-be PASS row as **VOID** with
`clock_resync=1`, so a resynced run cannot satisfy H1–H3. Any other value of
the variable is refused (VOID), and no clock is touched.

The NTP state of each cluster on 2026-10-31:

- loss, tcp and udp all carry the three-server `system ntp ... routing-instance
  mgmt` stanza, and all six nodes report `Leap status: Normal`. tcp's and udp's
  stanzas were committed that day; earlier that day tcp had none
  (`configuration path not found: system ntp`, both nodes
  `Not synchronised`), which is the state the no-stanza VOID is for. #18584 is
  closed.
- From 09:35 to 10:16 UTC both loss nodes lost every source (`no selectable
  sources (3 unreachable sources)`). With the stanza configured, a crash gate
  in such a window FAILs, unless the servers fail the orchestrator's SNTP
  probe too, in which case it is a lab NTP outage (VOID).
- Outside a crash gate, `test-connectivity` runs #18629's one-shot NTP health
  cell: it reads each node's stanza independently and measures both Leap
  statuses once. Both stanzas are required; a stanza missing on either node,
  an invalid skew bound, unreadable configuration, or unreadable/noisy
  measurement is VOID. Both synchronised and within
  `XPF_FAILOVER_CLOCK_SKEW_BOUND_S` (default 5 s) PASS; one unsynchronised
  node FAILs. If both are unsynchronised, an answering configured server or an
  unavailable off-path probe FAILs; a completed probe with no answers is a
  lab-outage VOID. The cell never waits for convergence or resyncs clocks.
  This surfaces chrony loss or node-specific NTP reachability before a crash smoke runs.

`make test-failover-clock-lib` (also in `make selftest`) covers this
hermetically, with mocked `incus`, `timeout`, `date` and `sleep` over a
virtual clock. Each node's exec latency is asymmetric and varies per sample,
so only the minimum-RTT midpoint reads the planted skew exactly: max-RTT,
one sample, and no midpoint all read it wrong. Its cells:

- converged; converges within the budget; the log lines;
- neither node synchronised: VOID without a stanza; with a stanza, FAIL when
  its servers answer the host or the probe is unavailable, VOID when none
  answers, VOID when the config is unreadable;
- one node synchronised (the #18584 class): FAIL with the rebooted node
  unsynchronised, whether or not the baseline already showed it (AD's A/B);
  FAIL with the peer unsynchronised or its chronyc silent, with or without
  a stanza;
- a chrony blip at the baseline instant does not decide anything (AC's
  probe: PASS after about 12 s); chrony lost on both nodes after a
  synchronised baseline (AD's D);
- each condition alone; the bound's edges with the error included (4.5 s
  PASS, 4.9 s and 5.5 s FAIL); too noisy; leap-second states; an unreadable
  clock;
- the escape (one host reading, banner, flag); an invalid escape value; the
  refusals; the measure-only reading;
- the cell helper; the host-side timeouts;
- the ledger contract with the real adapter;
- a spliced-in silent `date -s` on the measured path, and a runaway guard.

A static census scans every `.sh` and `.py` harness under `test/incus/` and
`scripts/` (self-tests excluded). It strips comment lines and folds quotes,
commas, brackets and parentheses to spaces. It then flags:

- `date` with a set flag anywhere in its arguments (`-s`, `-s@N`,
  `-s2026-…`, `-s"…"`, `"-s"`, `--set`, `-u -d X -s T`) or in the positional
  `MMDDhhmm[[CC]YY][.ss]` form; `timedatectl set-time`;
  `hwclock --hctosys|--systohc|-s|-w`; `chronyc makestep|settime`;
  `chronyd -q`; `ntpd -…q`; `ntpdate`; `adjtimex`; `sntp -s|-S`;
  `rdate -s`; `phc_ctl`; and Python `clock_settime`/`settimeofday`/
  `clock_adjtime` (including the `["date", "-s", …]` list form);
- any `failover_resync_node_clocks` call outside the library's escape;
- a file that sources the library (`source` or `.`) and never runs the check.

Each shape has a positive control. The file-level scan is first run on planted
fixtures: a dot-sourced direct call, an indirect one, Python forms, a quoted
flag, a comment and a sanctioned escape body. It reads text, so a command
assembled at run time (`eval`, a variable holding `date`) is outside its reach
and is left to review.

## What traffic must do

The status views say who SHOULD forward; the soak checks who DID (#18587
review). After landing it takes each helper's per-binding RX+TX packet
counters and again at the end of the window: the target node's members of the
RG's RETHs (from `show configuration | display set`) must carry at least
`SOAK_FOLLOW_MIN_PKTS` (500) packets in between and the other node's at most
10 % of that. For the LAN RG it also reads the LAN host's `ip -4 neigh show
<LAN VIP>` and, for IPv6, the neighbour entry of its RA default router (the
RETH link-local, e.g. `fe80::bf72:16:2` on loss — the global LAN VIP is not
what IPv6 traffic uses): each must resolve to the target node's per-node RETH MAC
(fw0 `02:bf:72:CC:RR:..` even, fw1 odd; the soak maps MACs to nodes from each
node's `ip -o link`). A move whose views and helpers flipped while the
packets stayed on the old node is a FAIL ("traffic did not follow"). RG0
(no RETH) has nothing to measure; a data RG that maps to no RETH members
voids the run rather than switching the check off.

Sessions are on both nodes before every planned move, so any lost packet is a
transition cost. The soak attributes every ping gap and iperf3 stall to the
move whose window it starts in. A window runs from the moment a move is issued
to the moment the next one is issued, on the LAN host's clock.

- **Ping** (`ping -D -i 0.01`, 100 pps, IPv4 to `$IPERF_TARGET4` and IPv6 to
  `$IPERF_TARGET6`). The soak reports lost replies and the longest gap per
  window, per family. Under `-P8` load the loss path drops a few pings with
  no move at all: on 2026-10-31, 20 windows in which nothing moved lost 0–4
  pings each, with the longest gap 21–39 ms.
- **iperf3** (IPv4 `-P8 -p 5211`, IPv6 `-P2 -p 5210`, `-i 0.1 --json-stream`).
  The worst per-stream stall is the longest run of 100 ms intervals under
  1 Mbit/s. A stream that disappears from the output counts as stalled from
  that point on; one that is still stalled at the end of the run never
  recovered, which is a FAIL of the move whose window it stalled in.
- **The window's tail.** In the last second of every window, ping must be
  answering and iperf3's aggregate must be above 1 Mbit/s. A move whose views
  agree while nothing forwards fails here.
- **Split RGs.** Moving RG2 (LAN) alone splits it from RG1 (WAN), so every
  flow crosses the fabric while RG2 is away. The tail aggregate with RG2 on
  node1 against node0 was about 9.6 against 39 Gbit/s on tcp, and about 2.7
  against 11.5 Gbit/s on loss: the copy-mode fabric ceiling,
  `docs/fabric-performance-optimizations.md`. That is expected, not a failure.
  - Part of those split figures was #18656, not the fabric. Flows that
    existed before the move ran on a per-packet slow-path loop on the new
    owner. On tcp, an IPv4 `SOAK_RG=2` soak's split-tail aggregate went from
    8.9 Gbit/s on master to 14.9 on the fix. An RG1-only soak went from 6.6
    to 15.5. Both were 12/12 PASS on both builds.
  - Under `-P8` the congested fabric also drops pings throughout the split
    window. On loss that was up to 66 per 5 s window, with no gap longer than
    87 ms.
  - So read "ping lost" against "longest gap": many short gaps spread over the
    window are congestion, and one long gap is the transition.
  - Use `SOAK_RG=all` to move the RGs together.

The hitless targets (at most 3 pings and no 200 ms stall per single-RG move)
are row H10's, tracked by #18559. H11 judges correctness, and **COST** is
deliberately narrow: ONE stream's stall over `SOAK_MAX_STALL_MS` (2 s) from
which it recovered, while ping stayed within `SOAK_MAX_GAP_MS` (1 s) and the
aggregate never went to zero for longer than that — TCP backoff after a short
loss, #18559's cost, judged master-relative like H10. On loss on 2026-10-31
that was 5 of 200 moves at 5 s and 1 of 60 at 2 s (single streams stalled
2.2–6.6 s, ping gaps never over 115 ms); scoring them FAIL would make a
40-move per-PR leg red most of the time on master. Everything wider is a
FAIL: a ping gap over 1 s, an aggregate (all-stream) outage over 1 s, a stall
past `SOAK_MAX_COST_STALL_MS` (10 s), a stream that never recovers. So "the
traffic stopped for a few seconds and came back" is never a pass.
`SOAK_STRICT_COST=1` scores COST as FAIL for a hitless-target run.

## Running the soak

```sh
# loss (default), 20 moves of RG2 from node0, 5 s apart
make test-rg-move-soak

# the user's cadence, long
SOAK_MOVES=200 SOAK_SLEEP=5 make test-rg-move-soak
SOAK_MOVES=200 SOAK_SLEEP=2 make test-rg-move-soak

# other shapes
SOAK_FROM=1 make test-rg-move-soak           # issue every move on node1
SOAK_FORM=untargeted-away make test-rg-move-soak  # moves away from the issuer untargeted (H1's form)
SOAK_RG=1 make test-rg-move-soak             # RG1 (WAN)
SOAK_RG=all make test-rg-move-soak           # every RG in status, each move

# tcp or udp: export the cluster's lock tuple too
BPFRX_CLUSTER_ENV=test/incus/tcp-userspace-cluster.env \
XPF_CLUSTER_LOCK=/var/worktrees/.cache/tmpdir/xpf-cluster-tcp.lock \
XPF_CLUSTER_OWNER=/var/worktrees/.cache/tmpdir/xpf-cluster-tcp.owner \
XPF_CLUSTER_EPOCH=/var/worktrees/.cache/tmpdir/xpf-cluster-state/epoch-tcp \
  ./test/incus/rg-move-soak.sh
```

The script (`test/incus/rg-move-soak.sh`, logic in `rg_move_soak.py`) takes
the cluster lock itself. It **never touches a clock**: the preflight measures
each node's offset from this host (the minimum-RTT `incus exec date` sample)
and prints the node1−node0 skew, with a warning at 10 s. It also prints each
node's `chronyc tracking`. The skew is measured again at the end.

Knobs:

| Variable | Default | Meaning |
|---|---|---|
| `SOAK_MOVES` | 20 | number of moves |
| `SOAK_SLEEP` | 5 | seconds after each CLI return before the next move |
| `SOAK_RG` | 2 | `2`, `1`, a list such as `1,2`, or `all` |
| `SOAK_FROM` | 0 | the node that issues every move |
| `SOAK_FORM` | `targeted` | `targeted`: every move is `redundancy-group <rg> node <t>`. `untargeted-away` (#18559): a move away from the issuing node is the operator's untargeted `redundancy-group <rg>`, run on that node (the owner); a move back is `... node <issuer>`. H1 issues its planned moves untargeted. The reply to an away-move is classed (`cli_classes` in the summary): `ok` = `... (transfer committed)`; `triggered` = the plain `Manual failover triggered for redundancy group N`, a pre-#18559 build, accepted (FAIL under `SOAK_EXPECT_TRANSFER=1`), its UDP checkpoint taken at the observed landing because a local resign confirms no commit; `fallback` = `Manual failover triggered ... (peer unreachable; resigned locally, break-before-make)`, `(the peer is also primary; resigned locally)`, or the OK `Redundancy group N is no longer primary on this node ...` (the group left by election during the request), a post-#18559 build that did not run the transfer, scored VOID with that reason |
| `SOAK_EXPECT_TRANSFER` | 0 | `1` (#18559): the build under test runs the untargeted form as a transfer, so a plain `triggered` reply on an away-move is a FAIL. Set it for post-#18559 runs; leave it 0 for a master control |
| `SOAK_CONVERGE_S` | `SOAK_SLEEP` | seconds after the CLI returns for the RG to land |
| `SOAK_MAX_GAP_MS` | 1000 | longest ping gap allowed in a move's window |
| `SOAK_MAX_STALL_MS` | 2000 | worst iperf3 stream stall allowed in a move's window |
| `SOAK_FOLLOW_MIN_PKTS` | 500 | RETH-member packets the target must carry between landing and the window's end |
| `SOAK_STRICT_COST` | 0 | `1`: a COST (over-budget but recovered) scores FAIL |
| `SOAK_MAX_COST_STALL_MS` | 10000 | a recovered single-stream stall longer than this is a FAIL, not COST |
| `SOAK_TRAFFIC` | 1 | `0`: control plane only (the run exits 2) |
| `SOAK_TRAFFIC_S` | 120 per RG move + 600 | iperf3/ping run length. The soak stops the generators itself after the last window, so this is a cap for a controller that dies (#19054) |
| `SOAK_HELPER_CHECK` | 1 | `0`: skip the helper reads (the run exits 2) |
| `SOAK_IPV6` | 1 | `0`: IPv4 only. IPv6 traffic-follow reads the LAN host's RA default router (a RETH link-local), which is what its IPv6 traffic uses; no default route, or an unmappable router MAC, voids the run |
| `SOAK_RESTORE` | 1 | `0`: do not put node0 back as primary at the end (matrix row D3) |
| `SOAK_IPERF_PORT` | 5211 | the unshaped CoS class on the loss path |
| `SOAK_IPERF6_PORT` | 5210 | IPv6 iperf3 server port |
| `SOAK_OUT` | `/var/tmp/rg-move-soak-<utc>` | artefacts: `soak.log`, `result.json`, `ping.log`, `iperf.jsonl`, `ping6.log`, `iperf6.jsonl` |

`make test-rg-move-soak` runs it through `harness-result.sh` (`smoke-cells`,
`--require-helper-attestation`), so a run writes a ledger row with build
attestation; the soak's last line, `rg-move-soak: <n> passed, <m> failed,
<k> cost`, is what the adapter scores (a correct move — PASS or COST —
passed) and the ledger records `cells_cost=<k>`. `ledger_compare.py` compares
only the headline (`cells_passed`), so the master-relative COST rule is
judged by hand from the recorded rows. Under `SOAK_STRICT_COST=1` the COST moves are counted in
`failed` and the row is a FAIL. At the
end the soak puts node0 back as primary for every RG it moved (a local pull
on node0, reported as `restore:`; never folded into the moves' verdicts).

With traffic on, a one-socket UDP sequence probe (#18679,
`udp_session_probe.py`) also runs from the LAN host. Before each move the
soak reads the probe flow's firewall Session ID on the target (the synced
standby), and at the end of the window it reads it again there (now the
primary). Each read is
`show security flow session source-prefix <client>/32 source-port <p>
destination-prefix <target>/32 destination-port 6201 protocol udp limit 10000`
on that node, and the soak parses only that node's own section. The tuple
filter and the explicit limit are required (#19038). The bare command stops
at 100 rows per node in BPF hash order (#19039), so on a busy node it showed
the probe on one node and not the other, by run rather than by issuer or
direction. The four loss runs at #18559's head took all four combinations.

The first move takes each RG away from its current owner. After that the
directions alternate strictly, whatever happened, exactly like the operator's
loop. After landing, the soak keeps sampling both views until the window
ends (the operator's `sleep S`), so a move that goes dual-active or reverts
two seconds after landing is caught.

The window always takes at least ONE sample (#19061). At `SOAK_SLEEP=2` the
landing poll, the UDP checkpoint and the helper reads could use up the whole
window. With no sample, the move's revert and post-landing dual-active
checks never ran, and the NEXT move's precondition came from an older move.
That gave a false VOID ("RG2 was on node0 before a move to node0") while the
journals showed RG2 on node1 the whole time. A window that has already
ended still gets its one sample, which delays the next move by one sample.
`result.json` records each RG's `window_samples` and `window_extended`.

## Pass criteria

One verdict per move:

- **PASS**: every condition in "What a correct move is" held.
- **COST**: the move was correct, but exactly ONE stream stalled over
  `SOAK_MAX_STALL_MS` and recovered within `SOAK_MAX_COST_STALL_MS`, while
  ping and the aggregate stayed within `SOAK_MAX_GAP_MS` (#18559). Counted,
  not failed; judged master-relative (row H11). `SOAK_STRICT_COST=1` makes it
  a FAIL.
- **FAIL**, for any of:
  - the CLI printed an error (including #18585's `cross-node request not
    sent` refusal);
  - the CLI said "already primary" although the RG was on the other node;
  - the CLI printed anything else unexpected;
  - the RG did not land in both views within the bound;
  - a dual-active sample anywhere in the move's window, or the RG leaving
    the target after landing;
  - a landing first seen by a read that finished past `SOAK_CONVERGE_S`
    after the CLI returned (#19041);
  - the helper disagreed with the views;
  - the traffic did not follow: the RETH-member counters or the LAN host's
    neighbour entry stayed on the old node, or nothing flowed in the
    window's tail (either family);
  - a ping gap over `SOAK_MAX_GAP_MS`, or every stream at once under
    1 Mbit/s for longer than that (an aggregate outage), in either family;
  - a stream stall past `SOAK_MAX_COST_STALL_MS`, more than one stream
    stalling over `SOAK_MAX_STALL_MS` in the window, or a stream that never
    recovered (still stalled when the traffic data ends, after more than
    `SOAK_MAX_COST_STALL_MS`);
  - a LAN neighbour entry (IPv4 VIP or IPv6 RA router) that resolves to no
    RETH MAC on a move, after the preflight proved it resolvable
    ("traffic-follow unmeasured");
- **VOID**: the precondition failed. Before a move to node *t*, the RG was not
  cleanly owned by the other node at the end of the previous window. A failed
  move therefore costs one FAIL, and the next move, back to where the RG
  still is, is VOID, not a second FAIL. The operator's "already primary"
  line is that cascade.
- **VOID, recovery not observable** (#19062): a stream was still stalled
  when the traffic stopped, but for no longer than `SOAK_MAX_COST_STALL_MS`,
  so the soak could not see whether it would recover.
  - After the last window the soak keeps the traffic running for
    `SOAK_MAX_COST_STALL_MS` + 2 s before stopping it, so this happens only
    when the traffic ended early.
  - Before #19062 the soak stopped the traffic 1 s after the last window.
    A 5 s stall that the same stream recovered from on every other move was
    then scored "never recovered" on the last one.
- **VOID, uncovered** (#19054): ping or iperf3 did not cover the move's
  window. Whatever the traffic checks say about a window with no traffic,
  they say it about nothing, so the move is never PASS or COST.
  - "Covered" means the generator PROCESS was seen still running at or
    after the window's END. The soak polls the processes right after each
    move is issued and after the last window.
  - Replies cannot prove coverage. A live ping behind a blackhole gets
    none; that window is covered, and its silence FAILs as a ping gap. A
    generator that exited 0.4 s before the window closed still had replies
    in the window's last second, and that once passed as covered.
  - The reason names the cause: the traffic run's planned end came first
    (`SOAK_TRAFFIC_S`), or a generator stopped early, with iperf3's error
    text when it has one.
  - Any other check that fired is listed as "unscored evidence".
  - Before #19054 the run length was estimated at sleep + converge + 4 s per
    move, plus 60 s. A 200-move run outlived it after about 182 moves, and
    the last 18 moves were scored FAIL on no traffic. Moves also took longer
    late in that run: about 11 s each at the start, 38 s at the end.

A **void run** (exit 2, `FATAL:` line, no moves scored) when the soak cannot
measure what it claims to: no RG with a single clean owner at preflight; the
LAN host clock unreadable; a traffic generator not streaming after the
warmup — a busy iperf3 server ("the server is busy running a test"), a dead
target; a Python error in the harness; SIGTERM (the LAN-host generators are
stopped first). None of these is a FAIL.

The run exits 0 when every move was PASS or COST, 1 on any FAIL, and 2 when
there was no FAIL but a VOID move, a void run, or a disabled check
(`SOAK_TRAFFIC=0` or `SOAK_HELPER_CHECK=0`: a run that measured less never
reads as a full pass).

Matrix row H11 states what an HA PR must show. The cells for every verdict
rule, and end-to-end runs against a fake cluster and LAN host (including
the operator's skew failure, traffic that never moved, a busy iperf3 server,
a late dual-active sample and a revert), are in
`test/incus/rg_move_soak_test.py` (`make test-rg-move-soak-lib`, also run by
`make selftest`).

### Sampling both nodes

Each node's own `show chassis cluster status` is a separate command, and
two commands never read one instant.

**History (#19041).** The soak used to run the two reads in parallel during
a move. A clean handoff could then be read as the old owner primary just
before it and the target primary just after it, with no real overlap. That
sample was scored as a dual-active FAIL, and it failed the harness's own
cells at random. For three review rounds, #19041 tried to clear such samples
with an immediate re-sample, and every round found another reading that the
re-sample cleared wrongly. That mechanism is gone.

**During a move**, in the landing poll and the rest of the window, the soak
reads the two nodes one after the other: the commanded TARGET first (T1),
then the old owner (T2 > T1).

- A clean, break-before-make handoff cannot show as dual-active in this
  order. If the target claims the RG at T1, the old owner had already let
  go before T1, so it reads released at T2.
- So every dual-active sample is scored and FAILs. Such a sample means one
  of two things, and both are failed moves:
  - the old owner still claimed the RG after the target had taken it: a
    real overlap, for example a make-before-break transfer whose old owner
    has not let go yet;
  - the target let go between T1 and T2 while the old owner took it back.
- After landing no handoff is pending, so the order no longer matters, and
  any dual-active sample is a real overlap or a second handoff. When one
  move takes several RGs to different targets (`SOAK_RG=all`), one sample
  serves them all in the move's own target-first order. That is safe for
  the same reason. An RG that never landed already FAILs "did not land".
- Limit: an overlap is seen only if one sample's target read (T1) AND
  that same sample's old-owner read (T2) both fall inside it, so the
  overlap has to span the sample from T1 to T2. The soak misses:
  - an overlap that started earlier and ends between a sample's two
    reads;
  - an overlap that falls between samples: the `poll_s` sleep (0.2 s)
    plus the reads around it;
  - an overlap that ends before the first sample after the CLI returns.
    `one_rg` takes no sample while the CLI call runs, so that call is never
    sampled. In #18559's gate artefacts it took 0.35-1.97 s, and it is
    where #18559's transfer runs. This gap predates #19041.
- Trade-off: two serial reads are about one full read apart, where
  parallel reads were 0 to about one read apart. Serial reads therefore
  raise the shortest overlap the soak can detect to about one full read.
  That is the price of never false-flagging a clean handoff. R16 measured
  it in the fake (0.15 s reads, `poll_s` 0.2 s): the longest real overlap
  that still PASSed was 0.64 s, against about 0.35 s for parallel reads at
  the same cadence.

**Known gaps** (filed; they predate #19041 and it does not fix them):

- [#19055](https://github.com/psaab/xpf/issues/19055), fixed: with
  `SOAK_RG=all`, the landing poll used to score only the RG being moved, so
  a dual-active overlap in an RG that had already landed earlier in the
  same move was missed until the window. Every landing-poll sample now
  scores every RG the run moves (see "Several RGs per move" below).
- [#19056](https://github.com/psaab/xpf/issues/19056), fixed: the LAN
  traffic windows were mapped from the controller's wall clock, so a
  wall-clock step on the controller could move a late ping gap or outage
  outside its move's window. They now come from the monotonic clock through
  an anchor taken at the offset measurement (see "Timing").

**Several RGs per move** (#19055). With `SOAK_RG` naming several RGs, each
move moves them one after the other. Every sample of every landing poll
reads all RGs, and each sample scores dual-active for every RG the run
moves, not only the one landing:

- An RG that already landed earlier in the move has no pending handoff,
  so a dual-active reading of it is real, and its own result records it.
- An RG not yet moved in this move is in the same position. The reading
  waits for its result.
- An RG moved earlier that did NOT land is skipped. Its handoff may still
  be in flight, read in another RG's order, and the move already FAILs
  "did not land".
- RGs outside `SOAK_RG` are not scored.

**Outside a move** (the preflight, the owner refresh before restore, and the
restore poll), the soak only asks who owns each RG and never scores
dual-active. Those reads stay parallel.

**Which line speaks for a node.** Each node prints its `Forwarding:` line
under its OWN row. The parser records the row a line sits under, and the
ownership check uses only a node's own line. A view whose own role row is
missing, whose own Forwarding line is missing, or whose value is not
`active`/`inactive` is unreadable. It cannot show a landing, and the joint
detail says "unreadable".

**Timing.** Deadlines and durations use a monotonic clock, so a wall-clock
step cannot stretch or shrink the landing bound. The move windows on the LAN
host's clock are monotonic too (#19056).
- When the preflight measures the LAN host's offset, the soak takes a
  (monotonic, wall) pair at the same moment.
- Every window edge is the monotonic moment mapped through that pair, plus
  the offset.
- A controller wall-clock step therefore cannot move a window. Before
  #19056, a 3 s backward step shortened the last window, and a late 1.5 s
  outage escaped it.
- A step of the LAN host's own clock is not detected.

A landing first seen by a read
that finished more than `SOAK_CONVERGE_S` after the CLI returned FAILs. A
sample is now two serial reads, so this is about one read later than with
parallel reads. In the #18559 gate's artefacts, landings were seen
0.30-0.99 s after the CLI returned, against a 2 or 5 s bound.

**Counts.** Each move's console line appends `dual_samples=N` when it saw
any dual-active sample. `summary` and `result.json` carry `dual_samples`.

**H11 comparability.** H11 runs scored before and after #19041 are not
comparable in two places:

- dual-active: there were parallel reads during a move before #19041;
- the landing bound: before #19041, a sample that started before the bound
  and saw the landing after it was a PASS.

A gate record that pairs runs across #19041 says which scorer each run
used.

**Cells.** The fake cluster reads each node at its own instant, like
production; its clock and shared state are locked for the parallel reads.

- `DualActiveScoring19041`:
  - drives the real `Soak.views()`, `IncusCluster.status()`, `one_rg()` and
    `watch_window()`;
  - uses a fake that flips ownership between the two reads, in both orders:
    target first never shows a clean handoff as dual, old owner first
    does;
  - checks that real overlaps FAIL;
  - checks that every shape the review seats used against the old
    re-sample ends FAIL;
  - checks the parser's line ownership and the monotonic landing bound.
- `DualActiveSampling19041` runs the cited Orchestration cells under 200
  deterministic interleavings of the remaining parallel reads.

## Reading a failure

| Reason in the table | What it means | Next step |
|---|---|---|
| `CLI error: ... fabric RPC authentication failed ... window Ns ahead/behind ours` `[fabric-auth clock skew ...]` | The node clocks are more than about 30 s apart. Every move to the peer is rejected | Check the preflight skew line and `chronyc tracking` on both nodes. Configure `system ntp server ... routing-instance mgmt` |
| `CLI error: ... cross-node request not sent: nodeN's wall clock is ...` `[inter-node clock skew]` | #18585's fail-fast: a fresh heartbeat reading says the clocks are 60 s or more apart, so the fabric RPC cannot authenticate and was not sent | Fix NTP; or issue the move on the target node (a local pull) |
| `unexpected CLI output: ...` | The CLI said something that is neither `transfer committed`, `already primary` nor an error, e.g. `Manual failover triggered` on a targeted move (it is accepted only for an `untargeted-away` move) or a superseded request | Check the command the soak issued; a superseded request means a concurrent `reset` |
| `CLI error: ... cannot connect to peer on any fabric address` (without auth) | The fabric path to the peer is down | Check fab0 addressing and reachability, and `show chassis cluster status` monitor failures |
| `CLI error: ... untargeted failover of redundancy group g ran as a make-before-break transfer to node N, which answered: ...` | `SOAK_FORM=untargeted-away`: the peer was reached and refused or failed the transfer (not takeover-ready, not transfer-ready, an `Unauthenticated` fabric token under 30-60 s of skew, an RPC error). No local resign ran (#18559) | Follow the reply's `Next:`, which is chosen by class: readiness (retry once ready), credentials (`code = Unauthenticated`: fix NTP, as in the first row), or the fabric path |
| `CLI error: ... code = Aborted ... ownership of redundancy group g changed during the request` | Ownership changed while the untargeted command ran (#18559): a newer move or an automatic election (an arm-debt yield-back, a flap) made the issuer primary again at a newer epoch. The group did not move, and no local resign ran. The text quotes the peer's reply, which may say `(transfer committed)`; that transfer was undone | Check `show chassis cluster status` and the election log for why ownership came back before retrying. With a single issuer it is more likely a revert than a racing operator |
| `fallback`, `Redundancy group g is no longer primary on this node ...` | The group already left the issuer while the untargeted command ran (the peer claimed it by election); the command succeeded (OK) and resigned nothing. It comes only from paths where the transfer did not run (the never-reached fallback, or dual-active), so the soak scores the move VOID "did not run the transfer" like the other fallbacks, and H1 counts it in `planned_reply_fallback`, which VOIDs the run. Not "unexpected CLI output" | Nothing to fix in the command; find out why the group moved by election during the move (the reply names the node that reports it primary; "no node reports it primary yet" means an election was still in progress) before trusting the next moves |
| `fallback`, `... (peer unreachable; resigned locally, break-before-make)` | An untargeted move whose request never reached the peer: the #18585 clock refusal, or no fabric address accepted a connection. It ran the pre-#18559 break-before-make resign, so the move is VOID, not PASS | Check the fabric path, as in the `cannot connect` row |
| `fallback`, `... (the peer is also primary; resigned locally)` | An untargeted move where the peer answered "already primary" while the issuing node was still primary at the same ownership epoch: both nodes claimed the RG, and the issuer resigned to end it. VOID, not PASS: no transfer ran | Find out why both nodes claimed the RG (control link, heartbeat, election logs) before trusting the next moves |
| `CLI error: ... not transfer-ready` / `barrier` / `fenced` / `peer config stale` | The transfer was refused by readiness, the sync barrier or a fence (#18521 class) | Check session-sync health (row H7). A refusal that clears on retry is still a FAIL |
| `CLI said already primary ... but the RG was on nodeX` | The issuing node's view disagrees with the joint view | Compare the two status outputs in `result.json`. This is a state bug |
| `did not land on nodeT within Ns` | The CLI returned, but the views never agreed in time. `last:` shows the final joint view | Check whether the RG landed later or not at all. Look for `secondary-hold` or `lost` |
| `landed on nodeT Xs after the CLI returned, past the Ys bound` | The RG landed, but the first read that saw it finished past `SOAK_CONVERGE_S` after the CLI returned (#19041). Any such read counts | Same as "did not land": the move was slower than the budget |
| `left nodeT after landing, inside the window` | The views agreed, then the RG moved again before the operator's next command (a preempt, an auto-failback, a racing request) | Pull both journals around the window; measure clock skew before pairing them |
| `dual-active: both nodes claimed it in one sample during the move window (<roles/Forwarding>; nodeT read first; N such sample(s))` | One sample read both nodes claiming the RG (role primary), or both forwarding it. During a move the target is read first, so this is the old owner still claiming the RG after the target took it, or the target giving it back (#19041) | Treat as severe: duplicate VIPs. Pull both journals. Measure clock skew before pairing them |
| `helper ha_groups[].forwarding_active disagrees` | The daemon's views agree, but the dataplane does not forward for the group (inactive, or active with an expired lease) | Check the helper's status and the daemon's RG apply path |
| `ping gap ... > budget` / `stream N stalled ...` | The move landed, but the transition cost more than the budget | Compare with H10's master baseline. A single bad window repeated across moves is a regression |
| `traffic did not follow to nodeT: RETH-member packets after landing node0=… node1=…` | Status and helper flipped, but the packets are still on the old node's RETH members | A forwarding/ownership divergence: check GARP/NA after the move, the helper's RG activation, fabric redirect |
| `traffic did not follow to nodeT: the LAN host's v4 neighbour entry ... still resolves to nodeN's MAC` | The LAN host still sends to the old owner's per-node RETH MAC | The new owner's GARP did not reach or was not accepted; check `garpEpoch` and the old owner's VIP removal |
| `traffic did not follow: no v4/v6 ping replies ...` / `... iperf3 aggregate under 1 Mbit/s ...` | The views moved, but nothing forwards in the window's tail | A forwarding or ownership divergence: check VIPs, neighbours and fabric redirect |
| `v4/v6 stream(s) [...] stalled in this window and never recovered` | A stream died at this move | The move killed sessions: check session sync for that flow, and #18531/#18535-class revocations |
| `v4/v6 stream(s) [...] were still stalled when the traffic stopped, before the N ms COST cap; recovery was not observable, so the move is unscored (#19062)` (VOID) | The traffic ended while a stream was stalled for less than the COST cap: the run (or `SOAK_TRAFFIC_S`) cut it off | Re-run with a longer `SOAK_TRAFFIC_S`, or check why the traffic ended early |
| `v4 ping gap N ms > 1000 ms` / `v4 aggregate outage: every stream under 1 Mbit/s for N ms` | The traffic stopped, not one TCP stream backing off | Treat as a transition failure: compare with H10's numbers and pull the journals for the window |
| COST: `v4 stream N stalled ... (recovered; ping and aggregate within budget)` | The move was correct; its transition cost exceeded the budget | Compare the run's COST count and stall distribution with master's (row H11, #18559) |
| `FATAL: preflight VOID: RGg has no single clean owner ...` / `cannot read the LAN host clock` | The cluster was not in a state a move can be judged from | Restore node0 primary (`SOAK_RESTORE`, row D3) and rerun |
| `FATAL: traffic preflight: v4 iperf3 to ... failed before any move: ... the server is busy running a test` / `not streaming` / `ping ... is not answering` | The traffic target is busy (another lane's iperf3) or unreachable | Check the target and the lock; rerun |
| `FATAL: harness error: ...` / `harness terminated by signal` | The harness itself failed; the generators were stopped | Fix the harness; the run measured nothing |
| `v4/v6 ping/iperf3 did not cover the move window: <cause>; the move is unscored (#19054)` (VOID) | The generators were not running for the whole window. `<cause>` is the planned end of the traffic run, or a generator that stopped early (with iperf3's error) | For the planned end, raise `SOAK_TRAFFIC_S`. For an early stop, read `iperf.jsonl`'s error event and `ping.log`. The move is VOID, not FAIL |
| `precondition: RGg was on nodeX before a move to nodeX` (VOID) | The previous move did not happen | Read the previous move's FAIL |
| `UDP sequence probe flow was absent on synced standby nodeN` (VOID) | The tuple-filtered listing on nodeN was complete (its `Total sessions:` equals the rows shown) and did not contain the probe flow: the standby really has no synced row for it | Check session sync (row H7) and the standby's `show security flow session destination-port 6201 limit 10000`. Before #19038 this line also came from the 100-row cap |
| `UDP sequence probe pre-move Session ID query failed: could not parse flow-session capture on nodeN: ...` or `UDP sequence probe final-window Session ID query failed: could not parse ...`, followed by `shows R rows but reports 'Total sessions: N'` or `no 'Total sessions:' terminator` (VOID) | The local listing was cut short, or has no `Total sessions:` terminator, so it cannot show the flow absent (#19038) | Under the tuple filter a cut listing means the CLI ignored the filter. Compare the CLI build with the query the soak sent |
| `UDP sequence probe pre-move Session ID query failed: could not capture flow sessions on nodeN: ...` or `UDP sequence probe final-window Session ID query failed: could not capture ...` (VOID) | The `cli -c` command or `incus exec` exited nonzero. A remote CLI error exits 1, for example a rejected filter token or `ResourceExhausted` from the session-walk limiter | Read the quoted output, and check the node's CLI and gRPC with the same command by hand |

## Measured

The rows below the first two predate the COST verdict and the
traffic-follow check (#18587 review): their "FAIL"s for stream stalls of
2.2–6.6 s would score COST today, and no row checked RETH counters or the
LAN neighbour entry.

| Date, cluster, build | Run | Result |
|---|---|---|
| 2026-10-31, loss, 0.0.26111+ge80f506bc2dc, fw1 72 s behind fw0, no NTP | 20 moves of RG2 from node0, 5 s | 10 FAIL (every move to node1: the fabric-auth clock error), 10 VOID (every move back: "already primary"). Traffic stayed on node0 throughout: 0–4 pings lost per window, longest gap 21–39 ms |
| 2026-10-31, tcp, 0.0.26066+gb5290d13d20d, clocks within about 1 s (no NTP) | 30 moves of RG2 from node0, 5 s | 30 PASS. CLI 0.53–0.78 s, landed 0.80–1.13 s after issue, 2–8 pings lost per move, longest gap 23–46 ms, worst stream stall 0–400 ms |
| 2026-10-31, loss, 0.0.26140+gacf27bc2bc3b (master plus #18587, #18589, #18590), clocks 0.2 s apart | 200 moves of RG2 from node0, 5 s | 195 PASS, 5 FAIL. Every move landed (CLI 0.9–1.4 s, landed ≤ 1.98 s, no dual-active, helpers agreed). Each FAIL is one iperf3 stream stalled 2.2–6.6 s (TCP backoff after loss at the activation point; #18559). Ping: longest gap ≤ 115 ms, but up to 66 pings lost per window while RG2 sat on node1, spread across the window. That loss is fabric congestion: RG2 alone on node1 carries every flow over the copy-mode fabric, with a tail of about 2.7 Gbit/s against 11.5 Gbit/s on node0 |
| same | 200 moves of RG2 from node0, 2 s | 200 PASS. CLI ≤ 1.41 s, landed ≤ 1.82 s, 5.5 pings lost per move (median; max 18), longest gap ≤ 95 ms, worst stall ≤ 1.5 s |
| 2026-10-31, udp, 0.0.26120+gcce3fb49443a, clocks within about 1 s (no NTP) | 40 moves of every RG (0, 1, 2; three commands per move) from node1, 2 s | 40 PASS. CLI 0.56–1.28 s per command, landed ≤ 1.72 s, 1–11 pings lost per move, longest gap 23–65 ms, worst stream stall 0–1.4 s |
