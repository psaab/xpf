---
status: REVISED v3 — Codex round-2 PLAN-NEEDS-MAJOR (data source doesn't exist as written; SessionTable.len() counts installed sessions not ingress-active flows); Gemini Pro 3.1 round-2 PLAN-NEEDS-MINOR (ingress-only counting + transient retx monitoring); v3 specifies a real ingress-active flow inventory mechanism, restores ≤20% CoV gate, scopes byte-rate selection to Phase 2 (Phase 1 picks "any 1s-active stable flow")
issue: #789 (parent), #936 (path A — declined for aggregate hit), #937 (path B — current scope)
phase: Single PR — closed-loop ntuple flow steering for shared_exact CoS classes (Phase 1 includes lifecycle + hysteresis + observability per round-1 review)
---

## 1. Issue framing

The user has explicitly asked for fairness across flows on Tier B
("don't let it fail. We need to solve fairness across flows").
Current state on master post-#1201/#1202 (2026-05-06):

| Class | P | CoV current | Gate (#789) |
|---|---|---:|---:|
| iperf-c | 12 | **62.5%** | ≤ 20% |
| iperf-c | 32 | 46.9% | ≤ 20% |
| iperf-b | 12 | 41.8% | ≤ 20% |
| iperf-b | 32 | 29.1% | ≤ 20% |
| iperf-a | 12 | 0.4% (PASS) | ≤ 20% |

iperf-c P=12 distribution shows classic RSS-bias signature (4
flows at 0.88-1.05, 3 at 1.27-1.33, 2 at 1.96-1.98, 3 at
3.84-3.93 Gb/s). iperf-a passes because the 1 Gb/s shape rate
divides cleanly across 12 flows.

## 2. Honest scope/value framing

### Verified premise (round-1)

Both Codex and Gemini Pro 3.1 confirmed:
- mlx5 `rxnfc`/ntuple programs the NIC's hardware flow director.
  Rules act at the **physical hardware level, before DMA, before
  any XDP program executes** (Gemini).
- This sidesteps the AF_XDP queue-binding wall at
  `userspace-xdp/src/lib.rs:1306-1308` because packets physically
  arrive on the steered RX queue → the per-queue XDP program →
  the per-queue AF_XDP socket.
- AF_XDP kernel docs confirm cross-queue XSKMAP redirects drop
  unless the socket matches the actual netdev/queue, and
  recommend NIC steering for cross-queue work (Codex).

### How this is distinct from prior dead-ends

- **#840 RSS-table tuning (REVERTED)** — the RSS indirection table
  maps hash buckets → queues. Tuning the table changes the bucket
  → queue mapping; existing flows whose hash is already in a
  bucket continue to land where the bucket points, except the
  per-PR-840 mechanism oscillated on bad signal and bucket
  granularity (per Codex round-1 correction — the #840 failure
  was bucket granularity + bad/oscillating signal, NOT lack of
  live-packet semantics; the correct distinction here is
  per-flow exact-match rules vs RSS bucket-rebalance rules).
  ntuple installs **per-5-tuple exact-match HW rules** that
  override RSS for the matching flow only. Distinct mechanism
  with distinct semantics.
- **#899 cross-binding XDP_REDIRECT (CLOSED 2026-04-25)** — XDP
  layer cross-queue redirect doesn't work; AF_XDP socket is
  queue-bound. ntuple acts BEFORE the XDP layer, so it doesn't
  hit this wall.
- **#946 Phase 2 (KILLED)** — order-coupled state in batched
  iteration. Unrelated mechanism.
- **#761, #747, #794, #838-afd-lite** — different dimensions
  (slot ledger, EWMA, AFD policer, AFD-lite). All preserved
  for context.

### Open paths

- **#936** — stall fast workers via shared per-flow finish-time
  table. ~43% aggregate hit on degenerate distributions.
  User-rejected as default-declined.
- **#937** — cross-binding flow re-steering. Limited by AF_XDP
  queue-binding wall. **mlx5 ntuple is the operational
  realization of the core idea** — re-steer happens at the NIC
  HW, not in software.

## 3. What's already shipped

- Per-binding AF_XDP queues + V_min sync (#917)
- BatchCounters disposition extension (#1202)
- BindingStatus telemetry surface in `protocol.rs:1149`
- Event-stream SessionOpen/Close codec
  (`userspace-dp/src/event_stream/codec.rs:40,58,194`)

## 4. Concrete design

This PR ships a single phase combining the lever, the lifecycle,
and the closed-loop controller — per round-1 review feedback,
the lifecycle and hysteresis cannot be deferred.

### 4.1 New module: `pkg/dataplane/userspace/flow_steering.go`

Go-side controller that owns NIC HW flow steering for
shared_exact CoS classes. Lifecycle:

1. **Daemon startup** — for each interface carrying a
   shared_exact CoS class (per resolved CoS config):
   - Detect parent NIC (handles VLAN sub-interface like
     `ge-0-0-2.80` → parent `ge-0-0-2`).
   - Verify driver is `mlx5_core` AND `ntuple-filters` toggleable
     (not `[fixed]`). If unsupported, log and skip; continue
     with RSS-as-today.
   - **Flush all xpfd-owned ntuple rules** before claiming
     ownership. Use a reserved location-id range (e.g., 32768+
     in a 64K table, configurable). Rules outside the range are
     not touched (preserves any operator-installed rules).
   - Enable `ntuple-filters on` if not already.
2. **Periodic tick** (1Hz) — `FlowSteeringController.Reconcile()`:
   - Pull `BindingStatus` from the userspace helper. Phase 1
     extends `BindingStatus` with `active_flows_count: u64`
     populated from `binding.flow.session_table.len()` on the
     worker side. Codex round-1 correctly identified that
     `per_binding` is ring-pressure, not flow inventory.
   - Group bindings by `(ifindex, queue_id) → flow_count` for
     each shared_exact-eligible interface.
   - Compute imbalance: `max_count - min_count`. If `< 2`, skip.
   - **Hysteresis gate (round-1 mandate):**
     - A binding whose flow_count moved in the prior tick is in
       a 3-tick cooldown window — skip until cooled.
     - A flow installed by the controller is in a 5-tick
       no-resteer window — track in
       `installed_rules: Map[FlowKey] → InstallTick`.
   - **Stable-flow gate (round-1 acknowledgement of transient
     aggregate hit):** only re-steer flows that have:
     - Existed for ≥ 3 prior reconcile ticks.
     - Accumulated ≥ 1 MB of bytes (to skip mid-handshake flows).
   - Pick K=1-2 flows with the highest byte-rate from the hot
     binding. Identify their wire 5-tuple per §4.2.
   - Install ntuple rules (`ethtool --config-ntuple <iface> ...`
     via netlink for low latency, OR shell out to `ethtool`
     command in Phase 1 for clarity).
   - Track installed rules in
     `installed_rules: Map[FlowKey] → (Iface, RuleLoc, InstallTime, TargetQueue)`.
3. **On flow termination** — when SessionClose event is
   received from event-stream (or when the conntrack GC
   surfaces a delete), tear down the corresponding ntuple rule.
4. **On daemon shutdown** — best-effort flush of all xpfd-owned
   rules. Uses the reserved location-id range so we know
   which rules are ours.
5. **On daemon crash** — startup flush (#1) covers this. Stale
   rules from a crashed instance get cleaned up at next startup
   before the controller begins installing new ones.

### 4.2 Wire 5-tuple semantics

ntuple rules match the packet **as the NIC sees it**:
- Direction is RX (ingress) only. ntuple rules cannot steer
  TX-side; outbound traffic goes via standard egress. This is
  fine — fairness is an ingress problem (which worker handles
  RX → forwarding decision).
- VLAN: rules on `ge-0-0-2` parent must include the VLAN tag
  filter (`vlan 80`) for VLAN 80 traffic. mlx5 ntuple supports
  VLAN tag matching.
- NAT: the userspace dataplane does NAT in software, so the NIC
  sees the **pre-NAT** wire tuple. The controller must capture
  the wire tuple from the inbound side, not the post-NAT
  internal `SessionKey`.
- IPv4 only in this PR; IPv6 (`flow-type tcp6`) is supported by
  mlx5 ntuple but deferred — the iperf-c P=12 baseline test is
  IPv4 (172.16.80.200).

### 4.3 Ingress-active flow inventory (Codex round-2 critical finding)

Codex round-2 correctly identified that `binding.flow.session_table.len()`
is the wrong surface — `binding.flow` is `WorkerFlowCacheState`,
not a session table; `SessionTable::len()` counts installed
sessions (not ingress-active); after a re-steer, the old worker's
session entry persists until session timeout (typically 30s+).

**v3 mechanism: per-session binding-slot stamping + recency-filtered
counting.**

Worker-side changes (`userspace-dp/src/session/mod.rs`):
- Add `installed_on_binding_slot: u32` field to `SessionEntry`
  (line ~111). Set at install time (`SessionTable::insert` or
  equivalent) to the slot value of the binding whose worker is
  currently processing the packet.
- New method `SessionTable::ingress_active_flows_for_binding(
  &self, slot: u32, now_ns: u64, recency_window_ns: u64) ->
  ActiveFlowInventory` returning:
  - `count: u32` — number of sessions where
    `installed_on_binding_slot == slot` AND
    `now_ns - last_seen_ns < recency_window_ns` (default 1s).
  - `top_k: SmallVec<[(SessionKey, last_seen_ns); 16]>` — up to K
    eligible flows for the controller to pick from. Phase 1 K=16.

`BindingStatus` (in `userspace-dp/src/protocol.rs:1149`) gains:
- `active_ingress_flows_count: u32` — projected from the new
  worker-side method.
- `active_ingress_flows_sample: Vec<ActiveFlowSample>` — up to 16
  recently-active ingress flow tuples with `(wire_5tuple,
  install_age_secs, last_seen_age_ms)`. Used by the controller to
  pick "stable" flows.

Phase 1 selects flows for re-steer using:
- Stability: `install_age_secs >= 3` (excludes mid-handshake)
- Recency: `last_seen_age_ms < 1000` (excludes idle/stale)
- Selection within those: deterministic by hash of 5-tuple (avoid
  arbitrary picks; reproducible logs).

**Byte-rate-based selection is DEFERRED to Phase 2** because
`SessionEntry` has no per-session byte counter today and adding
one to the worker hot path is non-trivial:
- Worker per-packet hot path would write to `entry.bytes_total +=
  packet_len` on every packet — adds 1 cache-line write per
  packet to the existing session entry.
- Acceptable cost (already touching the entry for `last_seen_ns`
  update) but worth measuring before committing.

For Phase 1, "any 1s-active stable ingress flow" is good enough
to demonstrate the mechanism. The Phase 0 experiment hit
CoV 3.8% with deterministic per-port-mod assignment, so even
imperfect flow selection should deliver a large CoV win.

**Phase 1 explicit limitation: only steer non-NAT flows.**
Detect via `decision.nat.is_some()` on the SessionEntry — skip
NAT'd flows for now. NAT-aware wire-tuple extraction
(reconstructing the pre-NAT tuple from SessionDecision metadata)
is Phase 3 hardening. The iperf-c shaper test case is direct
routing without SNAT/DNAT, so non-NAT scope covers it.

### 4.5 Configuration knob

Single CLI knob:

```
set system services userspace-dp flow-steering enable
```

Defaults: **disabled**. Operator must opt-in. This protects
against deployments where mlx5/ntuple isn't available or where
the operator doesn't want HW rules installed.

Per-class enable/disable deferred to a follow-up PR (Phase 2 in
v1 plan terminology).

### 4.6 Observability

New CLI command:
```
show cos flow-steering
```
Outputs per-class:
- Mechanism state (enabled / disabled / unsupported)
- Imbalance score history (last N ticks)
- Installed rules: count, target queue distribution
- Re-steer events: count, last 10 timestamps
- Aggregate-hit gate: pre-vs-post throughput / retx /
  session_misses counters around each re-steer

Prometheus counters:
- `xpf_userspace_flow_steering_rules_installed_total` (counter)
- `xpf_userspace_flow_steering_rules_removed_total` (counter)
- `xpf_userspace_flow_steering_imbalance_detected_total` (counter)
- `xpf_userspace_flow_steering_install_failures_total` (counter)
- `xpf_userspace_flow_steering_rule_table_capacity` (gauge)

## 5. Public API preservation

- New CLI knob (above).
- New CLI show command (above).
- New `active_flows_count` field on `BindingStatus`.
- New Prometheus counters/gauges.
- No breaking changes to existing API.

## 6. Hidden invariants the change must preserve

- **Existing RSS behavior unchanged when disabled** (default).
- **No interaction with the existing XDP redirect path.** ntuple
  steers at the NIC HW level, before XDP runs. The XDP program's
  current per-RX-queue logic continues unchanged.
- **Flow continuity.** A flow steered to queue Q at time T must
  continue arriving on Q until the rule is removed; ntuple rules
  are persistent until cleared.
- **Conntrack state.** Per Codex round-1, conntrack migration is
  less scary than originally claimed: session lookup falls back
  to shared sessions and materializes the hit locally. So
  re-steer triggers a `session_misses` increment + shared-map
  upsert, not full slow-path. Plan monitors
  `session_misses` / `session_creates` /
  `slow_path.injected_packets` deltas around each re-steer.
- **Aggregate transient hit (Gemini round-1)**: a re-steered
  flow may briefly drop throughput due to:
  - Packet reordering (in-flight on old queue + new on new queue)
    → TCP fast retransmit → cwnd cut.
  - Conntrack cold-start on receiving worker.
  Mitigation: stable-flow gate (1 MB + 3 ticks before re-steer)
  AND no-resteer cooldown (5 ticks).
- **Rule lifecycle on crash.** Reserved location-id range +
  startup flush ensures stale rules don't accumulate.

## 7. Risk assessment

| Class | Level | Why |
|---|---|---|
| Architectural mismatch | LOW | Both reviewers verified mlx5 ntuple is real HW redirect, not metadata; sidesteps AF_XDP wall by acting pre-XDP |
| Behavioral regression | LOW-MED | Default-off knob; only acts on detected imbalance; existing RSS path is fallback |
| Cross-driver portability | MED | Phase 1 limited to mlx5 (verified support). ice/i40e behavior different (different rule-table sizes, different CLI shape) — out of scope |
| Rule-table exhaustion | LOW | mlx5 typical 32k+ rules; 12-32 elephant flows trivial; controller bails on install failure |
| Rule lifecycle on crash | LOW | Reserved location-id range + startup flush handles this |
| Aggregate transient hit on re-steer | LOW-MED | Stable-flow gate + cooldown + monitoring; PASS gate is aggregate ≤ 5% regression averaged across runs |
| Conntrack cold-start | LOW | Per Codex, fast-path miss → shared-map lookup, NOT full slow-path |
| Ping-pong without hysteresis | MITIGATED | Mandatory hysteresis in Phase 1 (per Gemini round-1) |
| Operator surprise | LOW | Default-off; explicit knob; observability built in |

## 8. Test plan

- `cargo build --release`: clean
- `go test ./...`: pass
- Cargo tests: `cargo test --release` 974+ pass
- 5x flake on a new ntuple-rule-install integration test
- Smoke matrix on loss userspace cluster (default-off): 30 cells, 0 retrans (verifies we haven't regressed master)
- **Critical: per-flow CoV measurement** with mechanism enabled:
  - Enable: `set system services userspace-dp flow-steering enable`
  - Run iperf-c P=12 t=20 across 5 reps
  - Capture per-flow distribution, compute CoV
  - **PASS gate v2:**
    - CoV ≤ 20% on iperf-c P=12 (the #789 gate; per Codex round-2 — Phase 0 experiment hit 3.8% with deterministic mod-8 distribution, so the closed-loop controller picking stable ingress flows should clear ≤20% comfortably)
    - Aggregate ≥ 22 Gb/s averaged (no >5% regression vs 23.46 baseline)
    - Retransmit count ≤ 100 averaged
    - `session_misses` increment per re-steer ≤ 100
- Failover: `make test-failover` if accessible — verify rules re-install on activation, do not leak on failover.

## 9. Out of scope

- IPv6 ntuple support (defer; Phase 1 IPv4-only).
- ice/i40e driver portability.
- Per-class enable/disable knobs.
- Anything affecting iperf-a (passes already).
- Anything affecting non-shared_exact CoS classes (best-effort,
  bandwidth-limit, etc.) — fairness governed by shaper.
- Re-steer of UDP flows. ntuple supports UDP but Phase 1 is
  TCP-only.
- Re-steer of fragmented packets (rare).

## 10. Open questions for adversarial review (round-2)

1. **Rule-flush range.** Reserved range 32768+ — is that safe
   against operator-installed rules in mlx5 (which typically
   uses rule locs 0-32767 by default)? Or should we use a
   different reserved region?

2. **active_flows_count semantics.** `binding.flow.session_table.len()`
   includes BOTH ingress and egress sessions. For per-flow
   fairness, should the count only include sessions where this
   binding is the ingress side?

3. **Hysteresis tuning.** 3-tick cooldown / 5-tick no-resteer
   / 1 MB stable-flow gate — are these defensible defaults?
   What about a flow that bursts above 1 MB then idles?

4. **Conntrack surface area.** When a re-steered flow triggers
   `session_misses` on the new worker, the shared-map lookup
   takes a mutex. At 14.8M pps, is this a real cost? (Per #1187
   shipped, BatchCounters now batches `session_misses`, so the
   atomic isn't on hot path. But the shared-map mutex is.)

5. **NAT direction.** For the iperf-c case, traffic enters
   firewall → NAT (if any) → exits. The NIC sees the
   ingress-side wire tuple. Verify the controller captures the
   wire-side tuple, not the NAT'd internal tuple.

6. **iperf-c IPv6 scope.** The smoke matrix runs both v4 and v6
   per CLAUDE.md. Phase 1 is IPv4-only. Does the v6 baseline CoV
   regress relative to v4 CoV? If so, defer to follow-up PR
   that adds tcp6 ntuple.

7. **Aggregate-hit measurement methodology.** The plan claims
   "≥ 22 Gb/s averaged" as the PASS gate. Is averaging across
   5 reps statistically defensible at this aggregate variance?
   Or should we use min-of-5?

8. **Rule install via shell-out vs netlink.** Phase 1 plans to
   shell out to `ethtool` for clarity. At 1Hz with K=1-2 rules,
   the latency is fine. But it adds fork/exec cost
   (~ms) — can we use a Go ethtool library instead? (e.g.,
   `github.com/safchain/ethtool` or similar.)

## 11. Verdict request

PLAN-READY → execute Phase 1.
PLAN-NEEDS-MINOR → tweak (e.g., hysteresis defaults, reserved
range, observability surface).
PLAN-NEEDS-MAJOR → revise (e.g., stable-flow gate is wrong shape,
event-stream subscription needed instead of BindingStatus poll).
PLAN-KILL → premise still wrong despite round-1 verification
(unlikely — both reviewers confirmed the lever is real and
distinct from prior dead-ends).
