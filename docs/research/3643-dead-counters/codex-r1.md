**Verdict: PLAN-NEEDS-MAJOR**

Findings:

1. **POPULATE is not plan-ready because the hot-path cost claim is unsupported.**  
   The `ColdPathSlotMap` pattern is a decent sparse wire/slot-retention blueprint, but it is not proof of “2 non-atomic slot writes/pkt, no lookup.” Cold-path currently does a `HashMap` lookup in `lookup_slot` and only records after sampling fires: [cold_path_hist.rs](/home/ps/git/bpfrx/.claude/worktrees/3643-research/userspace-dp/src/afxdp/cold_path_hist.rs:279), [poll_descriptor/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/3643-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2266). For per-packet zone counters, the plan must specify where the resolved slot is cached or how it avoids a per-packet map lookup. If this follows `BatchCounters`, it also has atomic flush cost later: [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/3643-research/userspace-dp/src/afxdp/mod.rs:573).

2. **The read-side breakage claim is mostly correct, but the plan overstates several surfaces.**  
   Stable zone IDs are `[1,65533]`: [zoneid.go](/home/ps/git/bpfrx/.claude/worktrees/3643-research/pkg/config/zoneid.go:38). The userspace shim still exposes the dense-array readers through embedded `bpfShim`, with no `ReadZoneCounters` / `ReadFloodCounters` override: [legacy_dataplane.go](/home/ps/git/bpfrx/.claude/worktrees/3643-research/pkg/dataplane/userspace/legacy_dataplane.go:39). Dense reads return lookup errors for OOB keys: [maps_counters.go](/home/ps/git/bpfrx/.claude/worktrees/3643-research/pkg/dataplane/maps_counters.go:95), [maps_screen.go](/home/ps/git/bpfrx/.claude/worktrees/3643-research/pkg/dataplane/maps_screen.go:79). REST does 500 for zone reads, and Prometheus increments `xpf_counter_read_errors_total`: [security.go](/home/ps/git/bpfrx/.claude/worktrees/3643-research/pkg/api/security.go:104), [metrics_counters.go](/home/ps/git/bpfrx/.claude/worktrees/3643-research/pkg/api/metrics_counters.go:173). But flood counters are not REST/Prometheus surfaces today, Prometheus increments once per zone when ingress fails rather than “2x per zone,” and zone CLI gives an aggregate warning rather than per-zone error rows: [cli_show_security_zones.go](/home/ps/git/bpfrx/.claude/worktrees/3643-research/pkg/cli/cli_show_security_zones.go:172).

3. **Flood POPULATE is materially underspecified.**  
   Existing screen state has per-zone rate-limiter state, not cumulative per-zone flood event counters: [screen/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/3643-research/userspace-dp/src/screen/mod.rs:153). Durable accounting today is global/per-reason through `record_screen_drop`, not per-zone: [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/3643-research/userspace-dp/src/afxdp/mod.rs:564). So flood population is new accounting, likely on drop paths, not “snapshot existing state.”

4. **Clear/reset semantics are missing for POPULATE.**  
   The #2255 NAT clone is only mechanical for sparse read offsets. Once helper-reported cumulative counters exist, clearing only Go-side offsets will snap back on the next status poll unless the helper is also cleared or Go stores subtractive baselines. NAT explicitly handles this with helper IPC: [natcounters.go](/home/ps/git/bpfrx/.claude/worktrees/3643-research/pkg/dataplane/userspace/natcounters.go:7). Policy does the same in `ClearAllCounters`: [policycounters.go](/home/ps/git/bpfrx/.claude/worktrees/3643-research/pkg/dataplane/userspace/policycounters.go:163). Zone/flood needs the same contract.

5. **HA slot determinism is over-constrained if the wire carries zone IDs.**  
   I found no reason a public or cross-node surface should consume the slot as identity. Cold-path publishes slots, but meaningful labels come from zone IDs. Zone-counter slots can be node-local if Go ingests `{zone_id, counters}` and maps by zone ID. Do not make slot determinism an HA invariant unless the slot leaks into the API/wire as identity.

6. **DERIVE is correctly rejected, but the cited topology proof is weak.**  
   Userspace binds VLAN units to the parent netdev, so parent binding RX/TX cannot generally split traffic by logical VLAN-unit zone: [interfaces.go](/home/ps/git/bpfrx/.claude/worktrees/3643-research/pkg/dataplane/userspace/interfaces.go:90). That disqualifies DERIVE as a correct general solution. However, the loss-cluster example in `ha-cluster-userspace.conf` has `reth0.50` and `reth0.80` both in `wan`, not different zones: [ha-cluster-userspace.conf](/home/ps/git/bpfrx/.claude/worktrees/3643-research/docs/ha-cluster-userspace.conf:154). Use a multi-zone VLAN-parent example instead.

My hostile recommendation: approve the mandatory read-side sparse/unavailable fix only after the factual corrections above. Do not approve POPULATE until the plan nails slot resolution, batching/flush cost, helper clear semantics, flood-drop accounting, and the #3345 read-error contract. HIDE is a defensible product verdict if per-zone counters are not worth that complexity.

Codex session ID: 019f1d6e-3f35-72a3-93b6-614974ea1be5
Resume in Codex: codex resume 019f1d6e-3f35-72a3-93b6-614974ea1be5
