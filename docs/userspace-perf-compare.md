# Userspace Perf Compare

Use [userspace-perf-compare.sh](/home/ps/git/codex-xpf/scripts/userspace-perf-compare.sh) when you need a repeatable IPv4/IPv6 performance capture on the isolated userspace cluster without coupling the result to the pass/fail thresholds in `userspace-ha-validation.sh`.

This is the authoritative workflow for current-tree measurements. During active
performance work, do not cite the validation doc’s `22-23 Gbps` target as if it
describes the current tree state. Use this workflow and the saved artifacts instead.

This is the right tool when:
- the current tree is still unstable and validation fails at a reachability or throughput gate
- you still need current `perf` data from `xpf-userspace-fw0/1`
- you want a side-by-side IPv4/IPv6 hotspot comparison with saved artifacts
- you need to confirm whether a run is truly sustained or only bursts in the first second

Inputs:
- env: [loss-userspace-cluster.env](/home/ps/git/codex-xpf/test/incus/loss-userspace-cluster.env)
- isolated config: [ha-cluster-userspace.conf](/home/ps/git/codex-xpf/docs/ha-cluster-userspace.conf)
- validator: [userspace-ha-validation.sh](/home/ps/git/codex-xpf/scripts/userspace-ha-validation.sh)
- compare script: [userspace-perf-compare.sh](/home/ps/git/codex-xpf/scripts/userspace-perf-compare.sh)

Run:

```bash
./scripts/userspace-perf-compare.sh
./scripts/userspace-perf-compare.sh --duration 12 --parallel 4
```

What it does:
1. waits for CLI readiness on both isolated firewalls
2. ensures `cluster-userspace-host` is still accepting IPv6 RAs
3. detects the active userspace firewall instead of assuming `fw0`
4. records basic IPv4 and IPv6 reachability from `cluster-userspace-host`
5. runs one IPv4 `iperf3` capture to `172.16.80.200`
6. runs one IPv6 `iperf3` capture to `2001:559:8585:80::200`
7. records `perf` on the active firewall for each family
8. computes interval-level sustain metrics from the `iperf3 -J` artifacts
9. writes a compact markdown summary to `/tmp/userspace-perf-compare/summary.md`

Artifacts written under `/tmp/userspace-perf-compare`:
- `ipv4.json`
- `ipv4.err`
- `ipv4.perf.txt`
- `ipv6.json`
- `ipv6.err`
- `ipv6.perf.txt`
- `summary.md`

Interpretation rule:
- if `userspace-ha-validation.sh` passes, treat this script as profiling-only
- if validation fails, treat this script as the profiling/debugging path and use the reachability section first

Current expected hotspot categories:
- `xpf_userspace_dp::afxdp::poll_binding`
- `xpf_userspace_dp::afxdp::drain_pending_tx`
- `xpf_userspace_dp::afxdp::build_forwarded_frame_into` only when the run is
  private-UMEM direct TX or an explicit copy fallback. With cross-NIC
  shared-UMEM enabled, the normal LAN/WAN path should instead increment
  `In-place TX packets` and keep this builder out of the top profile.
- `xpf_userspace_dp::afxdp::apply_nat_ipv6`
- kernel AF_XDP copy or queue work such as `mlx5e_xsk_*`
- remaining lookup cost from route, neighbor, or session structures such as B-tree search

When interpreting the saved profile:

- compare IPv4 and IPv6 on the same active userspace node
- record `Direct TX`, `Copy-path TX`, `In-place TX`, and the in-place VLAN
  descriptor counters before and after the run; perf without those counters
  cannot distinguish private-UMEM direct TX from copy-free shared-UMEM TX
- treat forwarding failures or connect-then-stall runs as correctness bugs first,
  not as throughput numbers
- use the interval summary in `summary.md` to distinguish:
  - a genuinely steady run
  - a “fast first second, then cliff” run
- use the reachability section in `summary.md` before trusting any `perf` sample
