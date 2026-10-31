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
alternating moves indefinitely.

## What a correct move is

A move of RG *g* to node *t* is correct when all of these hold:

1. **The command tells the truth.** It reports
   `Manual failover completed for redundancy group g (transfer committed)` and
   the RG did move. "Already primary" is correct only when node *t* already
   owned *g*.
2. **Exactly one owner before and after, in both nodes' own views.**
   - node *t*'s `show chassis cluster status` shows itself `primary` for *g*;
   - the other node's own view shows itself `secondary` or `secondary-hold`
     (the untargeted yield parks the old owner in `secondary-hold`).
   - One node's view is not enough. node0's view alone scores a dual-primary
     split as healthy (the #18503 rule).
3. **Forwarding follows ownership.** Each node prints its own
   `Forwarding: rg-active=<active|inactive>` line under its own row (the
   daemon's *applied* RG state, #7367/#8326). The owner reads `active`, the
   other node `inactive`, and neither line carries a ` -- DIVERGENCE` suffix.
4. **The helper agrees.** Each node's userspace-dp helper reports
   `ha_groups[].active` true on *t* and false on the other node.
5. **No dual-active sample**, at any point during the move.
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
| `redundancy-group g` (no `node`) | `ManualFailover(g)`: A yields *g* (A goes to `secondary-hold`, the peer takes over). Run on the non-owner it moves nothing | local, then heartbeat/election | no |
| `data node N` | every data RG (ID > 0) not already on N, in one batch. To the local node it uses `RequestPeerFailoverBatch`; to the peer it is proxied like `node B` | as above | as above |
| `reset redundancy-group g` | `ResetFailover(g)`: clears the manual flag and hold on *this* node | local | no |

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
the wall clock. That is why a skewed cluster looks healthy in
`show chassis cluster status` while every cross-node RPC fails.

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
  `set system ntp server <address> routing-instance mgmt`. Since #18584, xpf
  renders this as chrony `bindacqdevice vrf-mgmt`
  (`/etc/chrony/conf.d/xpf-acquisition.conf`). chrony has one acquisition
  device, so every server must name the same instance. Mixed instances are
  committed with an advisory and not bound. A cluster whose servers use the
  default instance gets a commit advisory that names the secondary node. The
  lab cluster configs (`docs/ha-cluster-userspace.conf`, `-tcp`, `-udp`) carry
  this.
- Boot from a lagging RTC. The distro `chrony.conf` (kept by
  `scripts/image/bake.py`) carries `makestep 1 3`, so the first three clock
  updates after chronyd starts are stepped. xpfd restarts chrony once per
  daemon process after it first renders the binding. That covers a chronyd
  that started before `vrf-mgmt` existed, and it re-opens the step window.
  Measured on tcp fw1 (a secondary):
  `System clock was stepped by 1.103495 seconds` about 8 s after the restart.
- Visibility before the break. The nodes compare their wall clocks over the
  authenticated heartbeat and alarm well inside the 30 s window (#18585).
  Until that lands, `show chassis cluster status` carries only the post-break
  #6708 skew line, plus the local reference alarm (`pkg/clockskew`).

How to check a node:

```sh
incus exec <node> -- chronyc -n tracking | grep -E 'Reference|Leap|System time'
incus exec <node> -- chronyc -n sources
incus exec <node> -- cli -c 'show chassis cluster status' | grep -A3 Warning
```

## What traffic must do

Sessions are on both nodes before every planned move, so any lost packet is a
transition cost. The soak attributes every ping gap and iperf3 stall to the
move whose window it starts in. A window runs from the moment a move is issued
to the moment the next one is issued, on the LAN host's clock.

- **Ping** (`ping -D -i 0.01`, 100 pps). The soak reports lost replies and the
  longest gap per window. Under `-P8` load the loss path drops a few pings with
  no move at all: on 2026-10-31, 20 windows in which nothing moved lost 0–4
  pings each, with the longest gap 21–39 ms.
- **iperf3** (`-P8 -i 0.1 --json-stream`). The worst per-stream stall is the
  longest run of 100 ms intervals under 1 Mbit/s. A stream that disappears
  from the output counts as stalled from that point on.
- **The window's tail.** In the last second of every window, ping must be
  answering and iperf3's aggregate must be above 1 Mbit/s. A move whose views
  agree while nothing forwards fails here.
- **Split RGs.** Moving RG2 (LAN) alone splits it from RG1 (WAN), so every
  flow crosses the fabric while RG2 is away. On tcp the tail aggregate was
  about 9.6 Gbit/s with RG2 on node1 and about 39 Gbit/s with it on node0 (the
  copy-mode fabric ceiling, `docs/fabric-performance-optimizations.md`). That
  is expected, not a failure. Use `SOAK_RG=all` to move the RGs together.

The hitless targets (at most 3 pings and no 200 ms stall per single-RG move)
are row H10's, tracked by #18559. H11 judges correctness. Its default budgets
are wider so that it fails on a move that broke, not on today's known
transition cost.

## Running the soak

```sh
# loss (default), 20 moves of RG2 from node0, 5 s apart
make test-rg-move-soak

# the user's cadence, long
SOAK_MOVES=200 SOAK_SLEEP=5 make test-rg-move-soak
SOAK_MOVES=200 SOAK_SLEEP=2 make test-rg-move-soak

# other shapes
SOAK_FROM=1 make test-rg-move-soak           # issue every move on node1
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
| `SOAK_CONVERGE_S` | `SOAK_SLEEP` | seconds after the CLI returns for the RG to land |
| `SOAK_MAX_GAP_MS` | 1000 | longest ping gap allowed in a move's window |
| `SOAK_MAX_STALL_MS` | 2000 | worst iperf3 stream stall allowed in a move's window |
| `SOAK_TRAFFIC` | 1 | `0`: control plane only |
| `SOAK_HELPER_CHECK` | 1 | `0`: skip the helper `ha_groups` read |
| `SOAK_IPERF_PORT` | 5211 | the unshaped CoS class on the loss path |
| `SOAK_OUT` | `/var/tmp/rg-move-soak-<utc>` | artefacts: `soak.log`, `result.json`, `ping.log`, `iperf.jsonl` |

The first move takes each RG away from its current owner. After that the
directions alternate strictly, whatever happened, exactly like the operator's
loop.

## Pass criteria

One verdict per move:

- **PASS**: every condition in "What a correct move is" held.
- **FAIL**, for any of:
  - the CLI printed an error;
  - the CLI said "already primary" although the RG was on the other node;
  - the CLI printed anything else unexpected;
  - the RG did not land in both views within the bound;
  - a dual-active sample;
  - the helper disagreed with the views;
  - the ping gap or a stream stall was over budget;
  - traffic was absent in the window's tail;
  - ping or iperf3 stopped covering the window.
- **VOID**: the precondition failed. Before a move to node *t*, the RG was not
  cleanly owned by the other node. A failed move therefore costs one FAIL, and
  the next move, back to where the RG still is, is VOID, not a second FAIL.
  The operator's "already primary" line is that cascade.

The run exits 0 when every move passed, 1 on any FAIL, and 2 when there was no
FAIL but some VOID, or when the preflight was void (no RG with a single clean
owner, or an unreadable LAN host clock).

Matrix row H11 states what an HA PR must show. The cells for every verdict
rule, and an end-to-end run against a fake cluster that reproduces the
operator's failure, are in `test/incus/rg_move_soak_test.py`
(`make test-rg-move-soak-lib`, also run by `make selftest`).

## Reading a failure

| Reason in the table | What it means | Next step |
|---|---|---|
| `CLI error: ... fabric RPC authentication failed ... window Ns ahead/behind ours` `[fabric-auth clock skew ...]` | The node clocks are more than about 30 s apart. Every move to the peer is rejected | Check the preflight skew line and `chronyc tracking` on both nodes. Configure `system ntp server ... routing-instance mgmt` |
| `CLI error: ... cannot connect to peer on any fabric address` (without auth) | The fabric path to the peer is down | Check fab0 addressing and reachability, and `show chassis cluster status` monitor failures |
| `CLI error: ... not transfer-ready` / `barrier` / `fenced` / `peer config stale` | The transfer was refused by readiness, the sync barrier or a fence (#18521 class) | Check session-sync health (row H7). A refusal that clears on retry is still a FAIL |
| `CLI said already primary ... but the RG was on nodeX` | The issuing node's view disagrees with the joint view | Compare the two status outputs in `result.json`. This is a state bug |
| `did not land on nodeT within Ns` | The CLI returned, but the views never agreed in time. `last:` shows the final joint view | Check whether the RG landed later or not at all. Look for `secondary-hold` or `lost` |
| `dual-active sample` | Both nodes claimed the RG, or both forwarded it, at one sample | Treat as severe: duplicate VIPs. Pull both journals. Measure clock skew before pairing them |
| `helper ha_groups[].active disagrees` | The daemon's views agree, but the dataplane does not | Check the helper's status and the daemon's RG apply path |
| `ping gap ... > budget` / `stream N stalled ...` | The move landed, but the transition cost more than the budget | Compare with H10's master baseline. A single bad window repeated across moves is a regression |
| `traffic did not follow` | The views moved, but nothing forwards in the window's tail | A forwarding or ownership divergence: check VIPs, neighbours and fabric redirect |
| `ping/iperf3 did not cover the move window` | A traffic generator stopped (all streams died, or the client exited) | `iperf.jsonl` shows the error event. Streams dying is a FAIL of the move that killed them |
| `precondition: RGg was on nodeX before a move to nodeX` (VOID) | The previous move did not happen | Read the previous move's FAIL |

## Measured

| Date, cluster, build | Run | Result |
|---|---|---|
| 2026-10-31, loss, 0.0.26111+ge80f506bc2dc, fw1 72 s behind fw0, no NTP | 20 moves of RG2 from node0, 5 s | 10 FAIL (every move to node1: the fabric-auth clock error), 10 VOID (every move back: "already primary"). Traffic stayed on node0 throughout: 0–4 pings lost per window, longest gap 21–39 ms |
| 2026-10-31, tcp, 0.0.26066+gb5290d13d20d, clocks within about 1 s (no NTP) | 30 moves of RG2 from node0, 5 s | 30 PASS. CLI 0.53–0.78 s, landed 0.80–1.13 s after issue, 2–8 pings lost per move, longest gap 23–46 ms, worst stream stall 0–400 ms |
