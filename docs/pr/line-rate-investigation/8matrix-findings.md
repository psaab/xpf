# 8-matrix CoS validation — findings

Test: `iperf3 -c 172.16.80.200 -P 16 -t 60 -p <port> [-R]` for each
of 4 CoS-classified ports × 2 directions. Config:
`docs/pr/line-rate-investigation/full-cos.set` applied on
`loss:xpf-userspace-fw0` (primary after manual failover).

Note: `full-cos.set` was later amended by the low-rate validation work to add
q0/q4 buffer headroom. The raw JSON captures below predate those buffer-size
lines, so keep that provenance in mind when replaying the historical 8-matrix
evidence.

Raw JSON captures: `docs/pr/line-rate-investigation/evidence-8matrix/`.

## Results

| Port | Dir | Shaper | Target (96%) |  SUM   |  % shaper | CoV %  | Retr   | Status            |
|------|-----|--------|--------------|--------|-----------|--------|--------|-------------------|
| 5201 | fwd | 1.0G   | 0.96G        | 0.95G  |  95 %     | 25.58  |  300   | near (retr high) |
| 5201 | rev | 1.0G   | 0.96G        | 19.98G | **1998 %**| 35.53  | 7360   | **unshaped**      |
| 5202 | fwd | 10.0G  | 9.60G        | 9.55G  |  95 %     | 11.61  |    0   | near              |
| 5202 | rev | 10.0G  | 9.60G        | 19.71G | **197 %** | 71.85  |  484   | **unshaped**      |
| 5203 | fwd | 25.0G  | 24.0G        | 21.20G |  85 %     | 17.42  |    0   | NIC ceiling       |
| 5203 | rev | 25.0G  | 24.0G        | 19.71G |  79 %     | 35.86  |   58   | NIC ceiling       |
| 5204 | fwd | 0.1G   | 0.10G        | 0.10G  |  95 %     | 20.16  | 3702   | near (retr high)  |
| 5204 | rev | 0.1G   | 0.10G        | 19.29G |**19287 %**| 29.21  |  904   | **unshaped**      |

## Key finding — REVERSE direction is not shaped

Four of the eight test cells show reverse-direction throughput
independent of the shaper rate, landing uniformly around 19-20 Gbps.
Only p5203-rev falls below its nominal 25 G target — because at
that rate the shaper ceiling coincides with the NIC's forward
capacity, making "unshaped reverse" and "reverse shaped at 25 G"
indistinguishable.

### Root cause

The canonical CoS config applies `bandwidth-output` ONLY on the
reth0.80 OUTPUT direction. That filter:

- In the forward direction (client → fw → server), traffic exits
  via reth0 unit 80 → the filter fires → port-based classification
  → matching scheduler shapes.
- In the reverse direction (server → fw → client), traffic exits
  via ge-0-0-1 (the LAN-side interface) → **no filter attached**
  → no classification → no scheduler match → traffic forwarded
  at full fabric rate.

This is a CONFIG limitation, not an xpfd code bug. But it means
any "line-rate" evaluation that uses `-R` on the current config is
measuring forwarding capacity, not shaper enforcement.

### Follow-up: symmetric fixture

Issue #1250 adds `test/incus/cos-iperf-symmetric.set` as the
operator-supported fixture for both directions.

Important detail: reverse iperf3 `-R` data has **source-port**
5201/5202/5204 and an ephemeral destination port. A literal copy of
the forward `destination-port` terms onto `ge-0-0-1` would still leave
the reverse data unclassified. The symmetric fixture therefore uses:

- `bandwidth-output` on `reth0.80` output, matching
  `destination-port 5201..5207` for client → server data.
- `bandwidth-output-reverse` on `ge-0-0-1.0` output, matching
  `source-port 5201..5207` for server → client data.

The historical table above remains valid for the original
forward-only fixture. Do not use its reverse cells as scheduler-fairness
evidence.

### Remaining architecture options

1. **Symmetric output filters**: the #1250 fixture path. It is the
   lowest-risk validation fixture because each direction is classified
   at the egress interface that owns the shaper.

2. **Input filter on the WAN side**: apply an input filter on
   reth0.80 that does the same port-to-FC classification at
   ingress, and have the CoS system route reverse traffic through
   the matching queue at the local egress.

Either requires a config change to be considered; not in scope of
the line-rate investigation (which is per-port shaped-rate
compliance). The 8-matrix is captured here so future validation
can compare against the real shaping behaviour.

## Forward-direction assessment

Forward shaping IS working as expected. Three of four forward
cells hit 95 % of shaper rate (the expected steady-state for a
standard token-bucket shaper at the knee). The 96 % target was
optimistic — 95 % is the realistic steady-state for these shaper
sizes.

Retransmits are elevated on tightly-shaped ports (p5201 at 300,
p5204 at 3702). This is normal shaping behaviour: aggressive rate
limiting queues packets, and when the queue's tail-drop threshold
is exceeded, drops → retransmits. The p5201 rate of 300 retr /
60 s ≈ 5 retr/s is acceptable. p5204's 3702 retr / 60 s ≈ 62 retr/s
is higher and warrants investigation if 100 M best-effort is a
real operator target.

## p5203 (25 G shaper) — the actual line-rate test

Forward: 21.20 G, ~85 % of the 25 G shaper. Reverse: 19.71 G.
CoV 17-36 %.

This matches the prior investigation's gap of ~1-3 Gbps from line
rate; the 8-matrix test doesn't change that conclusion for p5203
alone. The broader finding (reverse-direction-unshaped) materially
changes what "line rate on all ports" means.

## Recommendations

1. **Update the investigation target**: redefine "line-rate
   validation" to include only the port/direction combinations
   where the CoS filter actually fires (i.e., forward direction
   for shaped ports + BOTH directions for whatever path matches
   at 25 G or the underlying link speed).

2. **Use #1250's symmetric fixture for reverse fairness work**:
   apply `test/incus/cos-iperf-symmetric.set` (or
   `apply-cos-config.sh --symmetric`) and require filter counters on
   `bandwidth-output-reverse` before treating reverse CoV as a
   scheduler signal.

3. **Forward-direction retr on p5204**: 62 retr/s on the 100M
   shaper is on the high side — worth a separate look if
   best-effort is load-bearing in any real deployment.

4. **Update #806 / remaining-gaps.md** to reflect these findings
   and refine the per-cell target accordingly (forward shapers
   ✓ at 95 %; reverse needs config change or be scoped out).
