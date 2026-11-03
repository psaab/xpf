---
name: iperf-grpc-tcpdump
description: Run synchronized iperf3 tests from the isolated userspace client while capturing server-side tcpdump over the gRPC capture service and simultaneous LAN/WAN tcpdumps on the active userspace firewall (kernel-visible control only; in-VM tcpdump is blind to AF_XDP fast-path flows, #16111). Use this when debugging throughput collapse, TCP resets, or tuple corruption on the userspace dataplane.
---

# iperf3 + gRPC tcpdump

Use this skill when the task is to reproduce or debug userspace dataplane
forwarding failures with synchronized captures.

This skill targets the isolated `loss` userspace lab:
- client: `loss:cluster-userspace-host`
- firewalls: `loss:xpf-userspace-fw0`, `loss:xpf-userspace-fw1`
- family 6 wire capture: gRPC endpoint `172.16.80.200:50051` on the
  external target box
- family 4 wire capture: `tcpdump` inside the IPv4 target container
  (`MOUSE_TARGET_NAME` from the cluster env, loss today
  `loss:xpf-mouse-target` at `IPERF_TARGET4` 172.16.80.202)

The helper script:
- detects the active firewall automatically
- family 6: starts the wire capture on the target box through `grpcurl`
  (`server-grpc.txt`); family 4: runs `tcpdump` inside the target
  container (`target-tcpdump.txt`), failing closed when it is missing
- starts LAN and WAN `tcpdump` on the active firewall
- runs `iperf3` from `cluster-userspace-host` against the env-selected
  `IPERF_TARGET4` / `IPERF_TARGET6`
- saves artifacts under `/tmp`

> **#16111 — in-VM `tcpdump` is blind to AF_XDP fast-path flows.** XDP
> redirects fast-path frames to the AF_XDP helper before any AF_PACKET
> tap, so the firewall-side `fw-lan.txt` / `fw-wan.txt` captures are
> kernel-visible control only: they may show control/slow-path traffic
> and background frames, but an empty file does not prove the iperf flow
> never traversed the firewall. The wire evidence is the target-side
> capture: `server-grpc.txt` for `--family 6`, `target-tcpdump.txt` for
> `--family 4` (and any LAN-host capture). Corroborate firewall traversal with the
> `fw-stats-before.txt` / `fw-stats-after.txt` deltas (`RX packets`,
> `Flow cache hits`): aggregate counters alone do not prove per-flow
> traversal on a busy node — they discriminate only for the isolated
> test flow or when corroborated by that wire capture; per-flow proof
> needs per-flow counters or session deltas. See
> `testing-docs/failover-testing.md` ("Observation points").

Run:

```bash
.codex/skills/iperf-grpc-tcpdump/scripts/capture_iperf.sh --family 4
.codex/skills/iperf-grpc-tcpdump/scripts/capture_iperf.sh --family 6
```

Useful options:

```bash
.codex/skills/iperf-grpc-tcpdump/scripts/capture_iperf.sh --family 4 --parallel 4 --duration 8
.codex/skills/iperf-grpc-tcpdump/scripts/capture_iperf.sh --family 6 --parallel 1 --duration 5 --cport 55340
```

Artifacts:
- `server-grpc.txt` (family 6 gRPC capture; family 4 placeholder note)
- `target-tcpdump.txt` (family 4 target-side capture; family 6 placeholder note)
- `fw-lan.txt`
- `fw-wan.txt`
- `fw-stats-before.txt`
- `fw-stats-after.txt`
- `iperf.json`
- `summary.txt`

Workflow:

1. Run the helper script for the family and stream count you want.
2. Read `summary.txt` first; note its `firewall_tcpdump_note=` line.
3. If throughput collapses after a strong first interval:
   - compare the wire capture (`server-grpc.txt` for family 6,
     `target-tcpdump.txt` for family 4) with the `fw-stats-before.txt` /
     `fw-stats-after.txt` deltas (`RX packets`, `Flow cache hits`,
     session hits/misses), subject to the busy-node qualification above
   - look for port drift, duplicate tuples, RSTs, or missing replies in
     that wire capture; treat `fw-lan.txt` / `fw-wan.txt` as
     kernel-visible control only, never as proof the flow was absent
4. Use `fw-stats-before.txt` and `fw-stats-after.txt` as corroboration
   (not standalone per-flow proof on a busy node) for whether the
   active firewall traversed the userspace dataplane; standalone proof
   needs the host/server captures plus per-flow counters or session
   deltas.

Assumptions:
- `incus` and `iperf3` are installed locally (`grpcurl` additionally
  for `--family 6`)
- the isolated userspace cluster already exists
- family 6: the gRPC capture service is reachable on
  `172.16.80.200:50051`; family 4: `tcpdump` is installed inside the
  target container (`MOUSE_TARGET_NAME`)

Do not use this skill to change cluster config or rebuild VMs. It is for
repeatable capture and analysis only.
