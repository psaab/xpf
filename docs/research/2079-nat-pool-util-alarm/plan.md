# Plan of Action — #2079 NAT pool-utilization-alarm has no consumer

- **Issue:** #2079 (`[audit] NAT pool-utilization-alarm is parsed and stored but has no consumer`)
- **Severity (audit-verified):** LOW
- **Revision:** r2 (folds r1 review: AGY M1-M5, Codex F1-F8, Claude SMR M1/m1-m3)
- **Status:** PLAN-READY (converged) — Claude SMR r2 PLAN-READY, AGY r2-retry
  PLAN-READY, Codex r1 PLAN-READY-WITH-NITS (all nits folded; Codex r2
  infra-dropped twice — `feedback_codex_infra_must_retry` exception applied)
- **Mode:** /research (stops at PLAN-READY; no code, no PR; awaiting `/engineer 2079`)
- **Recommendation:** Path B — alarm registry rendered in `show security alarms`
  (BOTH render sites) + transition-gated structured syslog, driven by a slow
  (10s) daemon monitor reading the cached 1 Hz userspace allocator pool snapshot.

### r2 changelog (resolved review findings)
- **CRITICAL fix to the design — DEDUPLICATE, do NOT sum, UsedPorts across rules.**
  AGY M1 + Codex F1 independently proved rules sharing a pool share the SAME
  `Arc<PortAllocatorShared>` (`allocator.rs:154`, `source.rs:282-290`
  `existing.clone()`), so every rule entry for a pool reports the IDENTICAL
  `UsedPorts`. Summing double/triple-counts → false alarms. r2 mandates
  dedup-by-pool-name, take one value. (was §6.2/§10 Q3 "sum" — now resolved)
- **Cached accessor, no socket I/O (AGY M2).** `Daemon.userspaceDataplaneStatus()`
  → `Manager.Status()` issues a blocking `ControlRequest{Type:"status"}`
  (`manager.go:1852`). r2 mandates a new cheap `Manager.LastStatus()` that
  returns `m.lastStatus` under lock (statusLoop already refreshes it at 1Hz in
  `process.go:393`). No new control-socket traffic.
- **Prune active alarms on pool removal/rename (AGY M3).**
- **Commit-time threshold validation (AGY M4 + Codex F7 + SMR m1).**
- **uint16 underflow-safe capacity math, guard PortLow>PortHigh (AGY M5 + Codex F4).**
- **BOTH render sites (Codex F2).** gRPC `Server.showSecurityAlarms`
  (`server_show_security_text.go:308`) AND local-CLI `CLI.showSecurityAlarms`
  (`cli_show_security.go:1788`) — else local CLI diverges.
- **Skip deterministic pools in r1 (SMR m3); broken existing surfaces noted
  (SMR F-OK3 + Codex F3).** `nat_port_counters` is NEVER incremented post
  eBPF-retirement — only seeded with a random offset — so `metrics_nat.go` +
  CLI `show security nat source pool` "Utilization %" are already garbage today
  (carved out as a follow-up).
- **Summary-vs-detail convention (SMR M1):** follow existing convention (count in
  summary, body in detail).
- Corrected §11 line refs (statusLoop is `process.go:393`, not manager.go).

---

## 1. Problem statement (verified)

`set security nat ... pool-utilization-alarm raise-threshold <N> clear-threshold <N>`
is parsed (`pkg/config/compiler_nat.go:334-366`, both hierarchical and flat-set
shapes) and stored on `NATConfig.PoolUtilizationAlarm`
(`pkg/config/types_security.go:241,251-255`). There is **no runtime consumer**:
`RaiseThreshold` / `ClearThreshold` are never read anywhere outside the compiler
and the type definition.

Verification (scoped to the research worktree, excluding sibling worktrees):

```
$ grep -rn "PoolUtilizationAlarm|RaiseThreshold|ClearThreshold" --include=*.go pkg/ cmd/ | grep -v _test.go
pkg/config/compiler_nat.go:336,342,348,357,362,366   # parse + store only
pkg/config/types_security.go:241,251,253,254          # type def only
```

No daemon loop, gRPC handler, CLI command, metric, syslog formatter, SNMP trap,
or event-engine source references the thresholds. The config is dead weight: an
operator who sets it gets silent no-op behaviour, contrary to vSRX where the
alarm raises a system alarm + (optionally) a syslog event + SNMP trap.

**Confirmed audit finding. The feature is genuinely unconsumed.**

---

## 2. Is the data already there? (the cheap-sampling question)

Yes. NAT source-pool utilization is **already tracked, already sampled at 1 Hz,
and already exposed** — only the threshold-crossing detection + delivery is
missing. This is the single most important fact in this plan because it removes
the hard part (dataplane accounting) entirely.

### 2a. Live source of truth — userspace allocator snapshot

`userspace-dp/src/nat/allocator.rs` keeps per-pool live state. `snapshot()`
(`allocator.rs:603-614`) reads it under one mutex lock and returns counts:
`used_ports = owner_by_translated.len()`, `live_flows`, `persistent_leases`,
plus cumulative `allocations_total` / `reuses_total` / `exhaustion_total`.

This is aggregated per source-NAT rule by `source_nat_pool_statuses()`
(`userspace-dp/src/nat/status.rs:9-34`) and serialized as the wire type
`SourceNatPoolStatus` (`userspace-dp/src/protocol/nat.rs:100-132`).

### 2b. Already flows to Go at 1 Hz — no new control traffic

The Rust helper embeds `Vec<SourceNatPoolStatus>` into the per-tick
`ProcessStatus` returned on the `"status"` control request. The Go manager
polls `"status"` once per second (`pkg/dataplane/userspace/manager.go`
statusLoop ~line 393, `lastStatus` cache at :110/:1094) and decodes into
`ProcessStatus.SourceNATPools []SourceNATPoolStatus`
(`pkg/dataplane/userspace/protocol.go:684,932-948`).

`SourceNATPoolStatus` carries **everything needed to compute utilization
without any new field**:

| Field | Use |
|-------|-----|
| `PoolName`, `RuleName` | identity / labels |
| `AddressCount` | capacity multiplier |
| `PortLow`, `PortHigh` | capacity per address |
| `UsedPorts` | numerator |

`utilization% = UsedPorts * 100 / (AddressCount * (PortHigh - PortLow + 1))`

**Sampling accessor (r2 correction — AGY M2):** the existing
`Daemon.userspaceDataplaneStatus()` (`daemon_forwarding_status.go:77-85`) calls
`Manager.Status()` which, when the helper is running, issues a **blocking
control-socket** `ControlRequest{Type:"status"}` (`manager.go:1852`). Using it on
a timer would add a redundant request per tick — forbidden by `CLAUDE.md`
"Control socket contention". r2 therefore mandates a NEW cheap accessor
`Manager.LastStatus() ProcessStatus` that returns the already-cached
`m.lastStatus` under the manager lock (no socket I/O). The statusLoop
(`process.go:393`) already refreshes `m.lastStatus` at 1Hz (`manager.go:1094`),
so the monitor reads in-memory state only. **Sampling cost: zero socket traffic,
no per-packet, no per-session work.**

### 2c. Already exposed as Prometheus metrics (the partial pre-existing "consumer")

`pkg/api/metrics_userspace.go:403-443` emits per-pool gauges from
`status.SourceNATPools`: `xpf_userspace_source_nat_pool_used_ports{pool,rule}`,
`...live_flows`, `...persistent_leases`, `..._total` counters.

> NOTE — DEAD legacy path (r2, sharpened by Codex F3 + SMR F-OK3, verified):
> `pkg/api/metrics_nat.go:12-54` and the CLI `show security nat source pool`
> (`pkg/cli/cli_show_nat.go:293-352`) read `dp.ReadNATPortCounter(poolID)` which
> looks up the eBPF map `nat_port_counters` (`maps_nat.go:387-401`). Post
> eBPF-retirement (#1373/#1476) **nothing increments that map** — verified:
> `grep nat_port_counter` over `userspace-dp/src/` and `userspace-xdp/src/`
> returns ZERO hits, and the only Go writer is `SeedNATPortCounters`
> (`maps_nat.go:407+`), which writes a one-time RANDOM offset at init. So
> `ReadNATPortCounter` returns a random seed value, NOT live utilization. The
> existing Prometheus gauge `xpf_nat_pool_used_ports` (`metrics_nat.go:35`) and
> the CLI "Ports allocated / Utilization %" (`cli_show_nat.go:328`) are therefore
> **already reporting garbage in userspace mode today.** The alarm MUST use the
> userspace allocator snapshot (`SourceNATPoolStatus.UsedPorts`), never
> `ReadNATPortCounter`. Fixing/removing the two broken legacy surfaces is a
> SEPARATE follow-up issue (out of scope for #2079; #2079 must not depend on it).

---

## 3. Delivery mechanism inventory (which "consumer" to build)

The audit's framing — "design the alarm-firing path" — is the real research
question, because there is no generic alarm-firing subsystem. Existing
candidate sinks:

| # | Mechanism | Exists? | Entry point | vSRX-faithful for this alarm? |
|---|-----------|---------|-------------|-------------------------------|
| A | **`show security alarms`** registry | YES (screen IDS + config warnings only) | `pkg/grpcapi/server_show_security_text.go:304-361` `showSecurityAlarms()` | **YES** — this is exactly where Junos surfaces NAT pool-util alarms |
| B | **Syslog structured event** (RT_NAT-style) | YES infra; no RT_NAT type | `pkg/logging/` EventReader/SyslogClient; formatters in `ringbuf.go` | YES (Junos logs `RT_NAT: ... pool utilization ... threshold`) |
| C | **SNMP trap** | YES infra (link traps only) | `pkg/snmp/traps.go`, `Agent.NotifyLinkUp/Down`; trap-group config exists (`compiler_system.go:722`) | PARTIAL — Junos has `jnxNatSrcPool*` traps, but ours would need a new enterprise OID |
| D | **Prometheus gauge + alert** | YES (`metrics_userspace.go`) | add `..._utilization_alarm_state{pool}` 0/1 gauge | Adjacent (not a Junos concept, but cheap + useful) |
| E | **Event engine** (`pkg/eventengine`) | YES (RPM-driven) | `Engine.HandleEvent` | Over-engineered for this; reserve as future |

### vSRX-faithful behaviour (what Junos actually does)

On vSRX/SRX, `pool-utilization-alarm raise-threshold/clear-threshold` causes the
device to, when a source pool's port (or address) utilization crosses the raise
threshold: (1) **raise a system alarm** visible in `show security alarms` (class
NAT), and (2) emit a NAT syslog message; on dropping below the clear threshold
the alarm clears and a clear event is logged. SNMP traps require an explicit
`jnxNatSrcPoolUtilization` trap config and are secondary. The primary,
expected-by-operators surface is **`show security alarms` + syslog**.

---

## 4. Multiple Path Options

### Path A — Alarm registry + `show security alarms` ONLY (minimal)
Add a daemon-resident monitor that reads the cached `ProcessStatus` on a slow
tick (e.g. 10s), computes per-pool utilization, applies raise/clear hysteresis,
and maintains an in-memory active-alarm set. `showSecurityAlarms()` renders the
active NAT pool alarms alongside the existing screen/config alarms.

- **Pros:** smallest blast radius; exactly the Junos primary surface; no new wire
  type, no SNMP OID, no syslog format invention; pure Go control-plane.
- **Cons:** an alarm that only appears in a `show` command is "pull-only" — no
  push notification to an external NMS/log collector. Junos itself also pushes a
  syslog line, so pure-A is slightly under-parity.

### Path B — Path A + structured syslog event (RECOMMENDED)
Path A, **plus** on each raise/clear transition emit one structured syslog line
through the existing `pkg/logging` syslog client (a new `RT_NAT`-style message,
or reuse the generic event path). One line per transition (not per tick) — fully
hysteresis-gated, so zero log spam.

- **Pros:** matches vSRX (registry + syslog push); transitions are rare events
  (`slog.Info`-class, per `CLAUDE.md` logging rules — NOT in a per-tick loop, the
  emit is gated behind a state change); gives external collectors a push signal;
  reuses fully-wired syslog infra.
- **Cons:** must define one structured message format (small) and decide
  facility/severity mapping. Slightly larger than A.

### Path C — Path B + SNMP trap + Prometheus alarm-state gauge (maximal)
Path B plus a new SNMP trap (`Agent.NotifyNATPoolAlarm`, new enterprise OID) and
a `xpf_..._pool_utilization_alarm_state{pool}` 0/1 gauge.

- **Pros:** every delivery channel covered; closest to a "full" feature.
- **Cons:** SNMP needs a new enterprise OID + MIB doc + trap PDU builder +
  trap-group plumbing — disproportionate for a LOW-severity audit fix. The
  Prometheus gauge duplicates information an operator can already derive
  (`used_ports / capacity`) via a Prometheus alert rule on existing gauges.

### PLAN-KILL option (explicitly weighed)
Delete the config knob + parser (refuse or warn on the stanza). **Rejected** —
the stanza is valid Junos syntax that operators copy from working vSRX configs;
silently accepting it is the current (bad) state, and refusing it would break
config-paste parity. vSRX parity is a core project goal (`CLAUDE.md`: "clones
Juniper vSRX capabilities using native Junos configuration syntax"). The feature
is low-effort to make real because the data already exists. KILL is not justified.

---

## 5. Recommendation: **Path B** (registry + `show security alarms` + structured syslog on transition)

Rationale (one sentence): Path B is the minimum that is **vSRX-faithful** (Junos
surfaces this alarm in `show security alarms` AND a syslog line), it reuses
infrastructure that is already wired end-to-end (the 1 Hz pool snapshot, the
alarm-render path, the syslog client), it adds zero per-packet / per-session /
extra-control-socket cost, and it defers the disproportionate SNMP-OID work to a
clearly-scoped follow-up. SNMP trap + Prometheus alarm gauge (Path C deltas)
become a small follow-up issue if an operator asks for push-to-NMS.

---

## 6. Proposed design (Path B)

### 6.1 New monitor (control plane, Go)
A small daemon-resident component (model: `pkg/ipmon` background engine, started
in `daemon_run.go` near `d.ipmon.Start()`). Either a new `pkg/natpoolalarm`
package or a method on the daemon — reviewer input welcome on placement; leaning
toward a self-contained, unit-testable struct that takes a `func() ProcessStatus`
sampler + `func() *config` + emit callbacks (dependency-injected so it is
testable without a live dataplane).

Loop (slow tick, **10s** — NOT 1s, to avoid flap; reads cached `LastStatus()`
only, no socket I/O):

```
status := dp.LastStatus()                       # cached, no socket request (r2)
alarmCfg := cfg.Security.NAT.PoolUtilizationAlarm
if alarmCfg == nil || alarmCfg.RaiseThreshold <= 0:   # disabled / unset (r2)
    clear-all-and-return

# r2: DEDUPLICATE by pool name — rules sharing a pool report the SAME UsedPorts
# (shared Arc<PortAllocatorShared>), so SUMMING would double-count. Take one.
byPool := {}                                     # pool_name -> SourceNATPoolStatus
for s in status.SourceNATPools:
    byPool[s.PoolName] = s                       # any entry; values identical per pool

for poolName, s in byPool:
    p, inCfg := cfg.Security.NAT.SourcePools[poolName]
    if !inCfg: continue                          # snapshot pool gone from cfg → prune handles it (avoids nil-deref)
    if p.Deterministic != nil: continue          # r2: skip det pools (UsedPorts != util; comma-ok guard)
    if s.AddressCount == 0 || s.PortHigh < s.PortLow: continue   # r2: guard underflow
    capacity := uint64(s.AddressCount) * uint64(s.PortHigh - s.PortLow + 1)
    if capacity == 0: continue                   # div-by-zero guard
    pct := s.UsedPorts * 100 / capacity
    raised := activeAlarms[poolName]
    if !raised && pct >= alarmCfg.RaiseThreshold: raise(poolName, pct)
    if  raised && pct <= alarmCfg.ClearThreshold: clear(poolName, pct)

# r2 (AGY M3): prune alarms for pools no longer in the snapshot/config
for poolName in activeAlarms:
    if poolName not in byPool: clearSilently(poolName)   # pool removed/renamed
```

`raise`/`clear` mutate the in-memory active-alarm set (guarded by a mutex; read
by BOTH `show security alarms` render sites — see §6.3) and emit one structured
syslog line on transition. Note `SourceNATPoolStatus` has no explicit
`Deterministic` flag today; r2 detects deterministic pools by cross-referencing
`cfg.Security.NAT.SourcePools[poolName].Deterministic != nil` (the config is the
source of truth for pool kind).

### 6.2 Hysteresis & matching semantics (r2 — RESOLVED)
- **Hysteresis:** raise on `>= RaiseThreshold`, clear on `<= ClearThreshold`,
  hold in between.
- **Commit-time validation (RESOLVED — was §10 Q1/Q2; AGY M4 + Codex F7):** add a
  hard validation block in the existing NAT validation section
  (`compiler_nat.go:369+`, same `return fmt.Errorf(...)` style as the
  deterministic-pool checks): require `0 < ClearThreshold < RaiseThreshold <=
  100`. This makes a bare `pool-utilization-alarm;` (which compiles to
  raise=0/clear=0, verified) a commit error rather than an always-firing alarm,
  and rejects inverted/equal thresholds. Defense-in-depth: the monitor also
  treats `RaiseThreshold <= 0` as "feature disabled". (Hard commit-reject chosen
  over a ValidateConfig warning because a misconfigured alarm is actively
  harmful — Junos itself requires raise > clear.)
- **Scope:** `NATConfig.PoolUtilizationAlarm` is a SINGLE GLOBAL raise/clear pair
  (matches Junos `set security nat source pool-utilization-alarm` global scope);
  same thresholds apply to every source pool; the registry keys on pool name.
- **Aggregation across rules (RESOLVED — was §10 Q3; AGY M1 + Codex F1, BOTH
  independently):** `SourceNATPoolStatus` is per-(rule,pool), BUT rules sharing a
  pool share the SAME `Arc<PortAllocatorShared>` (`allocator.rs:154`,
  `source.rs:282-290`), so every entry for a pool reports the IDENTICAL
  `UsedPorts`. **DEDUPLICATE by pool name and take one entry's value — do NOT
  sum** (summing double/triple-counts → false alarms). Capacity is
  pool-intrinsic (taken from one entry). A dedicated unit test must cover the
  two-rules-one-pool case and assert no double-count.
- **Deterministic pools (RESOLVED — SMR m3):** SKIP in r1 — `UsedPorts`
  (translated-tuple set) is not the right numerator for block-based deterministic
  pools; misreporting is worse than silence. Detected via
  `cfg...SourcePools[name].Deterministic != nil`. Block-based utilization is a
  follow-up.
- **Persistent-NAT:** `UsedPorts` still meaningful (in-use translated tuples);
  `PersistentLeases` is a secondary signal not used for the r1 raise/clear
  decision (could be a follow-up alarm dimension).

### 6.3 `show security alarms` integration — BOTH render sites (r2, Codex F2)
There are TWO independent implementations that must BOTH be updated or local-CLI
output diverges from gRPC/remote-CLI:
1. gRPC: `Server.showSecurityAlarms()` (`server_show_security_text.go:308`)
2. local CLI: `CLI.showSecurityAlarms()` (`cli_show_security.go:1788`, dispatched
   from `cli_show_security_dispatch.go:332`)

Both follow the existing **count-in-summary, body-in-detail** convention (SMR
M1): summary mode prints only the active-alarm count (`...:355-360`), detail mode
prints each alarm body. So NAT pool alarms bump the count in summary and render
`Class: NAT, Severity: Minor, Description: "NAT source pool <name> utilization
<pct>% exceeds raise-threshold <R>%"` (+ first-seen timestamp + current pct) in
detail — consistent with the existing screen/config alarms. Both handlers read
the monitor's active set via a thread-safe accessor. To avoid duplicating render
logic across the two sites, factor the active-alarm-to-lines formatting into a
shared helper consumed by both. Class/severity wording to mirror Junos.

### 6.4 Structured syslog on transition
On raise/clear, emit one line via the existing syslog client path. Reuse the
generic event emit or add a minimal `RT_NAT`-style formatter. Severity: raise →
warning/minor, clear → info/notice. Gated entirely behind the state transition →
at most a couple of lines per pool per utilization excursion. **No per-tick
logging** (complies with `CLAUDE.md` logging rules).

### 6.5 Out of scope for r1 (explicit)
- SNMP trap + enterprise OID/MIB (→ follow-up; Path C delta).
- `xpf_..._pool_utilization_alarm_state` Prometheus gauge (→ follow-up; derivable
  via alert rule on existing gauges today).
- Event-engine `pool-utilization-alarm` event source (→ future).
- Fixing/removing the dead `ReadNATPortCounter`/`metrics_nat.go`/CLI legacy
  eBPF-counter path that already reports garbage utilization in userspace mode
  (→ separate cleanup follow-up issue; #2079 must not depend on it). The natural
  fix there is to switch those surfaces to the allocator snapshot too, which
  #2079's monitor work makes easy — but it is a distinct change.
- Block-based utilization for deterministic pools (skipped in r1).
- `PersistentLeases`-dimension alarm; SNMP trap (Path C); Prometheus alarm-state
  gauge (Path C); event-engine pool-utilization event source.
- Per-pool (vs global) threshold override syntax (not in current Junos grammar
  parsed here).

---

## 7. Blast radius

- **New code:** one small monitor (Go), ~200-300 LOC + tests; a shared alarm-line
  formatter used by BOTH render sites; one syslog formatter + emit call; a new
  cheap `Manager.LastStatus()` accessor; daemon start/stop wiring; a commit-time
  validation block.
- **Touched files (estimated, r2):** `pkg/daemon/daemon_run.go` (start near
  `d.ipmon.Start()`), `pkg/daemon/daemon.go` (field), `pkg/dataplane/userspace/
  manager.go` (`LastStatus()` accessor), `pkg/grpcapi/server_show_security_text.go`
  (gRPC render), `pkg/cli/cli_show_security.go` (local-CLI render — Codex F2),
  `pkg/config/compiler_nat.go` (commit-time validation), new `pkg/natpoolalarm/*`
  (or `pkg/daemon/*`), `pkg/logging/*` (one formatter), docs.
- **No dataplane changes** (Rust untouched — data already published).
- **No new control-socket request** (reuses cached 1s status).
- **No wire-protocol change** (`SourceNATPoolStatus` already has all fields).
- **HA:** alarm state is node-local derived state, recomputed from each node's own
  dataplane snapshot — no session-sync / cluster-sync coupling, so **`make
  test-failover` is not gated** by correctness here (it must still pass as a
  no-regression check, but the change does not touch cluster/VRRP/sync code).

---

## 8. Test plan

- **Unit (Go), primary:** drive the monitor with a synthetic `ProcessStatus`
  sequence and assert raise fires once on crossing up, holds across the
  hysteresis band, clears once on crossing down, never double-fires, handles
  cap==0 (skip), `PortLow>PortHigh` (skip, no underflow), missing pool in
  snapshot, deterministic-pool skip, and — critically (r2) — **two rules sharing
  one pool must NOT double-count** (dedup test; assert pct computed from one
  entry, not the sum). Mutation test: deleting the emit call must fail a test.
- **Unit:** pool removed/renamed while alarm active → alarm is pruned, not stuck
  (AGY M3).
- **Unit (config):** `compiler_nat.go` rejects raise<=clear, out-of-range, and a
  bare `pool-utilization-alarm;` stanza (raise=0) at commit.
- **Unit:** `showSecurityAlarms` renders the active set (summary + detail).
- **Unit:** syslog formatter output shape (one line per transition).
- **`go test ./...`** + `go vet`.
- **Live smoke (loss userspace cluster):** configure a tiny pool (small port
  range so a handful of flows exceeds raise), drive iperf3/curl to allocate
  ports, confirm `show security alarms` shows the NAT alarm and a syslog line
  appears, then drain and confirm clear. Re-apply CoS after deploy (deploy wipes
  CoS). Verify no per-tick log spam in journald.
- **`make test-failover`** as no-regression gate (change is HA-neutral).

---

## 9. Risks / mitigations

| Risk | Mitigation |
|------|------------|
| `UsedPorts` from a multi-rule pool double-counts (shared Arc) | **Dedup by pool name, take one value (NOT sum)**; dedicated unit test (r2 — AGY M1/Codex F1) |
| Monitor adds control-socket traffic | Use new `Manager.LastStatus()` cached accessor, never `Status()` (r2 — AGY M2) |
| Active alarm stuck after pool removal/rename | Prune `activeAlarms` for absent pools each tick (r2 — AGY M3) |
| Local-CLI vs gRPC alarm output divergence | Update BOTH render sites via a shared formatter (r2 — Codex F2) |
| uint16 capacity underflow on `PortLow>PortHigh` | Guard + uint64 math (r2 — AGY M5/Codex F4) |
| Alarm flap near threshold | Hysteresis (raise!=clear) + slow 10s tick; commit-warn if raise<=clear |
| `clear=0` (unset) fires/clears spuriously | Define unset→default semantics at commit (open question §10) |
| Using the dead eBPF `ReadNATPortCounter` by mistake | Plan mandates allocator snapshot; code review must confirm |
| Log spam | Emit only on transition, never per tick (enforced by design + test) |
| Deterministic/persistent pool utilization semantics off | r1 uses raw UsedPorts; note follow-up; document the limitation |

---

## 10. Open questions — status after r2

RESOLVED in r2 (folded review):
- ~~Q1/Q2 threshold validation + unset semantics~~ → require `0 < clear < raise
  <= 100` as a hard commit error (`compiler_nat.go:369+`); monitor treats
  raise<=0 as disabled. (§6.2)
- ~~Q3 per-(rule,pool) vs per-pool aggregation~~ → DEDUPLICATE by pool name, take
  one value (shared Arc → identical UsedPorts). NOT sum. (§6.2)
- ~~Q7 UsedPorts numerator~~ → `owner_by_translated.len()` (in-use set) is the
  correct numerator (allocator round-robin is selection-only). (§2a)

Remaining (minor, non-blocking — engineer's discretion at /engineer):
1. **Monitor placement:** new `pkg/natpoolalarm` package vs a daemon method.
   Recommend: small injectable struct in its own package for testability
   (sampler `func() ProcessStatus` + config getter + emit callbacks DI'd).
2. **Tick interval:** 10s (alarm is not latency-critical; reads cached status).
3. **Severity/class wording** (Class NAT; Severity Minor on raise) — cosmetic;
   confirm against a real vSRX `show security alarms` sample if available.

---

## 11. References (file:line, research worktree)

- Parse/store (no consumer): `pkg/config/compiler_nat.go:334-366`,
  `pkg/config/types_security.go:241,251-255`
- Live utilization source: `userspace-dp/src/nat/allocator.rs:101-143,153-156,
  603-614`; shared-Arc dedup: `userspace-dp/src/nat/source.rs:130,202,282-290`;
  `userspace-dp/src/nat/status.rs:9-34`; `userspace-dp/src/protocol/nat.rs:100-132`
- Wire + Go status: `pkg/dataplane/userspace/protocol.go:684,932-948`;
  `lastStatus` field `manager.go:110`, refresh `manager.go:1094`, `Status()`
  (DOES socket I/O) `manager.go:1840-1862`; statusLoop `process.go:384,393`
- Daemon status accessor (does socket I/O): `daemon_forwarding_status.go:77-85`
- Existing Prometheus consumer (live, correct): `pkg/api/metrics_userspace.go:403-443`
- DEAD legacy eBPF counter path (never incremented; do NOT use):
  `pkg/api/metrics_nat.go:12-54`; `pkg/cli/cli_show_nat.go:293-352`;
  `pkg/dataplane/maps_nat.go:387-401` (read) + `:407+` (seed-only writer);
  `pkg/dataplane/loader_userspace_shim.go:52,292`
- Alarm render — BOTH sites: gRPC `pkg/grpcapi/server_show_security_text.go:304-361`;
  local CLI `pkg/cli/cli_show_security.go:1788` (dispatch
  `pkg/cli/cli_show_security_dispatch.go:332`)
- Commit-time validation site: `pkg/config/compiler_nat.go:369+`
- Syslog infra: `pkg/logging/syslog.go`, `pkg/logging/ringbuf.go`,
  `pkg/logging/eventbuf.go`, `pkg/daemon/daemon_system.go:24-138`
- SNMP infra (Path C only): `pkg/snmp/traps.go`, `pkg/snmp/agent.go`,
  `pkg/config/compiler_system.go:722`
- Monitor model: `pkg/ipmon` started at `pkg/daemon/daemon_run.go:463-495`
