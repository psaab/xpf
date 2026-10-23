# XPF userspace dataplane — throughput ceiling diagnosis

**Date:** 2026-10-21
**Trigger:** user — "the cpu is spinning all the workers at 8 cpus and at
10 cpus, so there must be a performance issue in the dataplane"
**Scope:** product dataplane (`userspace-dp` Rust helper + `userspace-xdp`
BPF steering program). This is NOT part of the tcp/udp test-firewall
setup plan; measurements were taken on the `tcp:` cluster because it was
the live rig at hand. Cluster state left by this work: TCP cluster in
`poll-mode interrupt`, workers 10 (see "Experiments" for why interrupt
was kept).

## Verdict

Confirmed. The userspace forwarding path costs roughly **1.9 µs
per packet** for a flow-cache-hit forward at 1500-byte MTU (basis
below; at an assumed ~3 GHz that is ~5,700 cycles — the VM has no
vPMU, so no hardware cycle count was measured). A lean AF_XDP
forwarder does the same hit-forward in roughly
500–1,000 cycles. There is no single hotspot: the cost is spread across
the kernel delivery path, a heavyweight XDP classifier, syscall traffic,
and the userspace descriptor path, plus per-tick housekeeping that runs
per batch per worker. Raising workers 6 → 10 did not raise throughput
because the per-packet cost, not the worker count, is the constraint;
the extra workers add contention (shared mutexes, host vCPUs) at the
same rate they add capacity.

## Measurements

Rig: TCP userspace HA cluster on host `tcp` (24 cores). Generator
container → fw0 (RG0/RG1 primary, 10 vCPU / 16 GiB) → target container,
`iperf3 -P32 -t15`, fresh `--one-off` server per run. All endpoints and
both firewall VMs are VFs/containers on the same host; the path never
leaves the host (mlx1 LAN hairpin + mlx0 WAN hairpin).

| Configuration | Throughput (-P32, own-cluster target) |
| --- | --- |
| 6 workers, 6 vCPU, interrupt (baseline) | ~36 Gbit/s (at -P4 validation) |
| 10 workers, 10 vCPU, interrupt | 34.5–36.7 Gbit/s |
| 10 workers, busy-poll | 37.5–38.3 Gbit/s |
| 10 workers, busy-poll, PPTP ALG disabled | 37.5 Gbit/s |
| 10 workers, interrupt, standby VM stopped | 37.7 Gbit/s |

Cross-cluster (TCP generator → UDP target `::211`) measured 44–50
Gbit/s in the same configuration — same workers, different endpoint
pair — i.e. the own-cluster target/container path also contributes, but
the firewall stack is the common ceiling.

Derived rate: data-plane RX counter delta 53.4M packets over the
measurement window. The window was not recorded alongside the delta,
so the packet rate is derived from the `perf` sample instead:
~83.5 CPU-seconds of worker CPU per 10 s wall at 37 Gbit/s over
~44M packets in that 10 s (≈4.4M pps aggregate across 10 queues,
~440k pps/queue) → ~1.9 µs/packet all-in (83.5 s ÷ 44M; kernel +
userspace attributed to worker threads). The 53.4M counter delta
spans a longer, unrecorded window (≈12 s at 4.4M pps) and must not
be divided by 10 s — doing so gives 5.34M pps / 1.56 µs and
contradicts the sampled basis above. Gbit/s↔pps cross-checks at
1500-byte MTU are approximate (frame overhead and counter scope —
RX-only vs forwarded — are not separated in the recorded data).

VM has no vPMU (`perf stat` cycles/instructions `<not supported>`), so
cycles/packet is derived from task-clock samples, not hardware
counters. In-guest `perf record` requires an explicit `-o` path; the
default output filename resolves to null and the data file silently
does not exist.

## Where the cycles go

Flat + inclusive `perf report` on `xpf-userspace-dp` under the load
above (busy-poll capture; shares are of worker-thread CPU):

| Cost centre | Share | Notes |
| --- | --- | --- |
| XDP steering BPF program | 8.6% self | `bpf_prog_*` — see below |
| Kernel mlx5 XSK receive + softirq | ~15% incl. | `mlx5e_napi_poll`, `mlx5e_xsk_skb_from_cqe_mpwrq_linear`, `handle_softirqs` |
| `sendto` TX kick | 10.6% incl. (6.5% `xsk_sendmsg` self) | syscall + kernel TX processing |
| Futex waits | 8.3% incl. | `__x64_sys_futex`/`do_futex`; see PPTP item |
| Userspace descriptor processing | 9.9% self | `poll_binding_process_descriptor_with_injection` |
| Worker loop body | 7.7% self | includes busy-poll spin; per-tick housekeeping inline |
| PPTP inbox drain | 5.5% self | `drain_pptp_control_inbox_at_epoch` — empty-queue no-op in this traffic |
| `std` mutex slow path | 3.8% self; `__pv_queued_spin_lock_slowpath` 4.5% | contention on shared state |
| Delta recovery | 1.8% | per-tick |
| Session-key hash, rewrite, misc | ~1% each | long tail of dozens of sub-1% functions |

Interpretation: even deleting any single line item buys at most ~10%.
The ceiling is the *sum* of: kernel XSK delivery + a classifier-grade
XDP program + per-batch syscalls + a feature-complete userspace
descriptor path + per-tick housekeeping. At ~440k pps/queue, one vCPU
per queue (worker thread + its NAPI softirq share) has a ~2.3 µs/packet
budget and the stack spends nearly all of it.

## Code-level findings

1. **The XDP program is a second dataplane, not a steering shim.**
   `userspace-xdp/src/lib.rs` (2,754 lines): per packet it parses L2
   (VLAN/S-tag/QinQ adjudication), parses IPv4/IPv6 including
   extension-header walks, classifies GRE/WireGuard, applies an early
   filter, and consults NAT/session state ("Interface-NAT session miss:
   redirect to helper") before `USERSPACE_XSK_MAP.redirect`. Every
   packet pays classifier cost in BPF and then pays adjudication again
   in userspace.

2. **PPTP inbox: interval gate checked under a shared lock.**
   `userspace-dp/src/session/pptp_control.rs`: `take_pending_in_domain`
   (line ~196) and the three `take_*_retries` (~443–493) each acquire
   the single inbox `inner` mutex *first* and check the 1-second
   `CONTROL_DRAIN_INTERVAL_NS` gate *second*. Called from
   `run_pptp_control_drain` every worker tick (`worker/loop_body/
   mod.rs` ~1522), that is 4 global-mutex acquisitions per worker per
   tick to return empty vectors. PPTP ALG is enabled by default
   (`forwarding_build` test: "default (no disable, no GRE accel) must
   enable PPTP"), so this runs even with zero PPTP traffic. This is the
   same defect class the codebase already fixed for zone counters
   (#5163: lock-free because "every worker used to bounce [the shared
   store mutex] at line rate"). A/B result: disabling the PPTP ALG
   removed the drain+futex cost but did **not** raise throughput
   (38.3 → 37.5 Gbit/s) — wasted cycles, not the cap. Cheap fix
   regardless: lock-free gate pre-check (atomic last-drain timestamp)
   before taking the mutex.

3. **TX/RX wake syscalls are already gate-optimised; the remaining
   `sendto` share is kernel TX work.** `userspace-dp/src/afxdp/tx/
   rings.rs` (~254–341) documents the earlier fix (ungated wake was
   142K syscalls/s ≈ 20% CPU). What remains in profile is largely
   `xsk_sendmsg` doing actual transmit processing per kick — batch
   depth per kick is the lever, not the kick gate.

4. **UMEM is not hugepage-backed.** Data-plane statistics:
   `Hugepage-backed bindings: 0/30`, `UMEM fallback bytes: 5033164800`.
   4 KiB-page UMEM across ~5 GiB guarantees TLB pressure on every frame
   touch. Minor next to items 1–3, but free to fix at bind time.

5. **Busy-poll burns the host without buying throughput here.**
   Both VMs at 10 vCPU busy-poll on a 24-core host held host load
   average ~21 *with no test running* (standby workers spin too), and
   in-guest steal time measured 10.8%. Interrupt mode matched busy-poll
   throughput within noise and cut retransmits ~6× (17,440 → 2,644 per
   15 s run). Left the cluster in interrupt mode.

## Ruled out (with evidence)

- **Worker count** — 6 vs 10 workers: no scaling (above table).
- **Host CPU contention** — standby VM fully stopped: 37.7 Gbit/s.
- **Endpoints** — during load, generator container iperf at 70% of one
  core, target at 210%, both ~32% idle overall.
- **Packet drops in the firewall** — cumulative counters at 597M RX:
  TX errors 0, RX ring-full 266, flow-cache hits 597,035,662 / misses
  634, copy-path TX 0 (all in-place). The 2.6–17k retransmits per run
  are not explained by firewall drops.
- **Queue/RSS imbalance** — 11 combined channels per guest VF observed;
  flows distribute across workers (all workers busy under load).
- **Jumbo frames as a workaround** — blocked by product gap: `mtu
  9000` in config does not propagate to guest netdevs and
  `ip link set ge-* mtu 9000` on XDP-attached interfaces returns
  `Invalid argument`. At 1500-byte MTU the packet rate (and therefore
  the ceiling) is what it is; 9000-byte frames would cut it ~6×.

## Fix candidates (unranked by ROI — needs a perf owner)

1. Slim the XDP program to queue steering only (parse ethertype/VLAN,
   redirect by RSS queue); move GRE/WG/NAT adjudication to the
   userspace path that already re-adjudicates. Removes the double
   adjudication and most of the 8.6% BPF self time.
2. Increase TX batch depth per `sendto` kick; audit RX fill/completion
   batch sizes for the same amortisation.
3. Lock-free interval-gate pre-check in `session/pptp_control.rs`
   `take_*` family (defect class of #5163). Cheap, safe, removes the
   futex convoy; do it even though A/B shows it is not the cap.
4. Hugepage-backed UMEM at bind time (`Hugepage-backed bindings:
   0/30` today).
5. Revisit per-tick housekeeping cadence: expiry/conntrack/delta/
   export slices run per worker per batch; confirm each is amortised
   at pps rates, not just at idle rates.

Realistic expectation: items 1+2 are the only ones plausibly worth
tens of percent. None of this changes the MTU-1500 packet-rate
arithmetic; without jumbo support (item: MTU propagation to
XDP-attached netdevs), ~40–50 Gbit/s at 1500 B is close to what this
cost stack can do regardless of workers.
