# #9506 IPsec live fixture and T12/G2 evidence

Date: 2026-09-19
Final matrix archive: `/var/tmp/xpf-t12-g2-9506-1789844895/`
Final matrix source SHA: `3e9a03fb0c32a11b002a831eecc11eaf80c0e717`
Final matrix executable SHA (local and both firewalls): `90b2cf4d29e1a8e9712514d78f3c2662a4db70cb3a4cd0cc3cafcb728c459f0b`
Final matrix result: `cells=30 pass=0 fail=0 void=30 exe_check=MATCH`; the harness exits 2 when the complete matrix contains only VOID rows.

## Fixture inventory

The fixture is isolated to the loss userspace cluster and is created by
`test/incus/ipsec-9506-fixture.sh` under `with-cluster.sh`:

- Peer container: `loss:xpf-ipsec-peer-9506`.
- Peer outer endpoints: WAN `172.16.50.202` /
  `2001:559:8585:50::202`; LAN `10.0.61.201` /
  `2001:559:8585:ef00::201`.
- Firewall outer endpoints: WAN `172.16.50.8` /
  `2001:559:8585:50::8`; LAN `10.0.61.1` /
  `2001:559:8585:ef00::1`.
- Even tunnel indexes use the WAN half and odd indexes use the LAN half.
  The fixture pins RG2 to node1 while live, then restores the recorded owner and
  manual/failover state.
- Firewall tunnel interfaces are `st9506.N`, with `if_id = 9506 << 16 | (N+1)`;
  the live kernel renders these links as `st9506.N@NONE`.
- Peer inner networks are `192.168.(100+N).0/24` and
  `2001:db8:9506:N::/64`. Each peer connection has a unique inner local TS and
  the shared LAN remote TS.
- IKEv2/ESP proposals are `aes128-sha256-modp2048`. The peer and firewalls use
  one lab PSK from `XPF_9506_IPSEC_PSK`; the default lab value is never written
  into this log. NAT-T shapes use peer `encap = yes` and firewall
  `nat-traversal force`; merged product fix #10474 renders the firewall side as
  swanctl-native `encap = yes` (without the rejected legacy `forceencaps` key).
- The peer image installs `strongswan`, `strongswan-swanctl`, `iproute2`,
  `iperf3`, `iputils-ping`, `python3`, and `tcpdump`. The FW1 baseline lacked
  `nft`; it was repaired once through the management VRF with the distro
  `nftables` package before the fixture run. Both nodes then passed the readable
  nft observer precondition.

The peer installs source-specific rules (priority 50) for all four outer peer
addresses so IKE/ESP replies use the main outer path rather than the inner
strongSwan table. The fixture also installs and removes explicit kernel routes
for every inner prefix through its `stN`; generated Junos static routes alone
did not populate the kernel route lookup in this lab. These are fixture-owned
routes and are removed before config/peer teardown.

## Live convergence and queue evidence

The final run converged every requested shape and tunnel count:

- 2-tunnel T12 fixture: `stn=2/2 sa=1/1 queues=8/8 nft=1/1`.
- 8 tunnels: `stn=8/8 sa=4/4 queues=32/32`.
- 16 tunnels: `stn=16/16 sa=8/8 queues=64/64`.
- 32 tunnels: `stn=32/32 sa=16/16 queues=128/128`.

The final 32-tunnel NAT-T fixture archive contains `fixture-queues.txt` with
IDs `1000..1127`. The node probes now read the real
`/proc/net/netfilter/nfnetlink_queue` table; for example, the final FW0 probe
contains all fixture queue IDs with `peer_portid`, `queue_total=2`, and no
kernel error. This replaces the previous nonexistent `nf_queue` path. Queue
class counts are `32/32/32/32` (inet input, inet output, bridge forward,
bridge input) on each firewall for the 32-tunnel cells. nft JSON is readable on
both nodes.

The convergence proof establishes live route-based links, SAs, divert queue
shape, and nft readability. It does not establish packet reinjection or
provenance: the available workload observer records `packets=0`, `loss_pct=100`,
and an independently scoped tunnel-0 XFRM state delta of `4`. Because the
harness has no attached/detached listener identity or reinjection observer, the
run does not attribute the delivery loss to a particular queue consumer or
barrier fault.

## Cleanup and restore proof

Teardown order is explicit and idempotent:

1. Terminate only fixture-owned IKE SAs.
2. Remove fixture-owned v4/v6 kernel inner routes.
3. Merge the generated fixture delete set and commit.
4. Record whether `security ike`, `security ipsec`, and `security address-book global`
   existed before setup. Remove a now-empty parent only when it was absent from
   that baseline and the full display-set proves it has no children; unrelated
   operator configuration is never deleted.
5. Poll both nodes for `stN`, XFRM state/policy, divert queue IDs, and nft residue.
6. Restore recorded RG2 ownership/manual state and delete the peer container.

Final harness restore line:

```
T12_G2_RESTORE fw0_config_cmp=1 fw1_config_cmp=1 fw0_residue_clear=1 fw1_residue_clear=1 residue_probe_error=0 archive=/var/tmp/xpf-t12-g2-9506-1789844895
```

Independent post-run audit under the cluster lock reported:

```
fw0 stn=0 xfrm=0 sa=0 queues=0 0 0 0 0
fw1 stn=0 xfrm=0 sa=0 queues=0 0 0 0 0
config_hits=absent
peer=absent
RG2 node1 (the recorded pre-run owner), manual=no
```

## Final 30-cell ledger

The 12 T12 rows are all VOID because the harness lacks the required exact
rule/provenance/transition observers; none is promoted to PASS from static
shape evidence.

| Gate | r6 section | Verdict / reason |
|---|---|---|
| `t12_9506_fence_shape` | §5.2.1 | VOID — `measurement-incomplete:exact-armed-pinhole-set` |
| `t12_9506_divert_order` | §5.2.2–§5.2.3 | VOID — `measurement-incomplete:exact-provenance-rule-set` |
| `t12_9506_no_bypass` | §5.2.4–§5.2.5 | VOID — `harness-void` (q0 surface and bidirectional delivery matrix absent) |
| `t12_9506_vrf_refusal` | §5.2.5a | VOID — `harness-void` (test VRF/ACK observer absent) |
| `t12_9506_coexistence_order` | §5.2.3 | VOID — `harness-void` |
| `t12_9506_provenance_metadata` | §5.2.3–§5.2.4 | VOID — `harness-void` |
| `t12_9506_ifindex_recreate` | §5.2.3–§5.2.4 | VOID — `harness-void` |
| `t12_9506_bridge_conformance` | §5.2.5 | VOID — `harness-void` |
| `t12_9506_l2_refusal` | §5.2.4–§5.2.5 | VOID — `harness-void` |
| `t12_9506_rotation_atomicity` | §5.2.3 | VOID — `harness-void` |
| `t12_9506_integration_ownership` | §5.2.6 | VOID — `harness-void` |
| `t12_9506_pf_bind_scope` | §5.2.2–§5.2.6 | VOID — `harness-void` |

The six non-workload G2 rows are also VOID because their dedicated observers
are not implemented:

| Gate | r6 section | Reason |
|---|---|---|
| `g2_9506_fence_baseline` | §5.1 | `measurement-incomplete:fence-baseline-observer-unavailable` |
| `g2_9506_divert_detached` | §5.1 | `measurement-incomplete:detached-listener-observer-unavailable` |
| `g2_9506_divert_idle` | §5.1 | `measurement-incomplete:idle-listener-observer-unavailable` |
| `g2_9506_capture_8t` | §5.1 | `measurement-incomplete:provenance-observer-unavailable` |
| `g2_9506_vrf_overhead` | §5.1 | `measurement-incomplete:vrf-refusal-observer-unavailable` |
| `g2_9506_queue_economics` | §5.1 | `measurement-incomplete:queue-economics-observer-unavailable` |

The remaining 12 G2 rows all reached a real fixture and are VOID solely for
missing provenance/non-tunnel-overhead observation. Each row had
`packets=0`, `xfrm_tunnel0_packets=4`, `loss_pct=100`, `teardown=1`, and
`restore_clean=1`:

| Shape | 8 tunnels | 16 tunnels | 32 tunnels |
|---|---|---|---|
| `v4_native` | `g2_9506_v4_native_8`: queues 32/32, classes 8/8/8/8 | `g2_9506_v4_native_16`: queues 64/64, classes 16/16/16/16 | `g2_9506_v4_native_32`: queues 128/128, classes 32/32/32/32 |
| `v4_nat_t` | `g2_9506_v4_nat_t_8`: queues 32/32, classes 8/8/8/8 | `g2_9506_v4_nat_t_16`: queues 64/64, classes 16/16/16/16 | `g2_9506_v4_nat_t_32`: queues 128/128, classes 32/32/32/32 |
| `v6_native` | `g2_9506_v6_native_8`: queues 32/32, classes 8/8/8/8 | `g2_9506_v6_native_16`: queues 64/64, classes 16/16/16/16 | `g2_9506_v6_native_32`: queues 128/128, classes 32/32/32/32 |
| `v6_nat_t` | `g2_9506_v6_nat_t_8`: queues 32/32, classes 8/8/8/8 | `g2_9506_v6_nat_t_16`: queues 64/64, classes 16/16/16/16 | `g2_9506_v6_nat_t_32`: queues 128/128, classes 32/32/32/32 |

All 12 use reason `measurement-incomplete:provenance-and-overhead-observer-unavailable`.

The exact machine-readable rows from this run are the 30 JSON records written
under `test/results/ledger.d/` at `2026-09-19T19:25:44Z–19:25:45Z` (all carry
`build_git_sha=3e9a03fb...`, `running_exe_sha256=90b2cf4d...`, and
`exe_check=MATCH`).

## Remaining acceptance work

This fixture lane is complete and restored, but the matrix is not
Closes-ready: every row is VOID. The remaining work is implementing the
provenance, listener/reinjection, non-tunnel overhead, VRF transition, and
exact fence/pinhole observers required by r6 §5.1/§5.2. The NAT-T renderer
precondition is no longer a remainder: product issue #10474 is merged as
`f4048596d` and all four NAT-T shape/count rows reached live SAs in this run.
