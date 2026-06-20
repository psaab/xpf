# Plan of Action — #2079 NAT pool-utilization-alarm has no consumer

- **Issue:** #2079 (`[audit] NAT pool-utilization-alarm is parsed and stored but has no consumer`)
- **Severity (audit-verified):** LOW
- **Revision:** r1
- **Status:** DRAFT — under 3-way hostile plan review (Claude SMR + Codex + AGY)
- **Mode:** /research (PLAN-READY or PLAN-KILL; no code, no PR)

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

The daemon already has an accessor: `Daemon.userspaceDataplaneStatus()`
(`pkg/daemon/daemon_forwarding_status.go:77-85`) returning the cached
`ProcessStatus`. **Sampling cost: zero new work — it reuses the existing 1s
snapshot already in memory.** No per-packet, no per-session, no extra control
socket request (which `CLAUDE.md` "Control socket contention" explicitly
forbids at >1/s).

### 2c. Already exposed as Prometheus metrics (the partial pre-existing "consumer")

`pkg/api/metrics_userspace.go:403-443` emits per-pool gauges from
`status.SourceNATPools`: `xpf_userspace_source_nat_pool_used_ports{pool,rule}`,
`...live_flows`, `...persistent_leases`, `..._total` counters.

> NOTE — dead legacy path: `pkg/api/metrics_nat.go:12-54` and the CLI
> `show security nat source pool` (`pkg/cli/cli_show_nat.go:293-352`) read
> `dp.ReadNATPortCounter(poolID)` which looks up the **eBPF map**
> `nat_port_counters` (`pkg/dataplane/maps_nat.go:387-401`). Post eBPF-retirement
> (#1373/#1476) that map is a "retained shim shared state"
> (`loader_userspace_shim.go:52,292`) — the AF_XDP shim may still increment a
> raw round-robin counter there, but it is NOT the authoritative live in-use
> port count. The plan MUST use the userspace allocator snapshot
> (`SourceNATPoolStatus.UsedPorts`), not `ReadNATPortCounter`, for alarm
> decisions. (Fixing the dead Prometheus/CLI path is out of scope for #2079 but
> noted as a follow-up.)

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

Loop (slow tick, e.g. 10s — NOT 1s, to avoid flap and stay well clear of the
control-socket contention rule; it reads the **already-cached** status so the
tick is just a recompute, no I/O):

```
for each pool in cfg.Security.NAT.SourcePools:
    cap   = AddressCount * (PortHigh - PortLow + 1)          # from snapshot
    used  = snapshot.SourceNATPools[pool].UsedPorts          # by PoolName(+Rule)
    if cap == 0: skip (avoid div-by-zero; emit nothing)
    pct   = used * 100 / cap
    raised = activeAlarms[pool]
    if !raised && pct >= RaiseThreshold:    raise(pool, pct)
    if  raised && pct <= ClearThreshold:    clear(pool, pct)
```

`raise`/`clear` mutate the in-memory active-alarm set (guarded by a mutex; read
by the gRPC `show security alarms` handler) and emit one structured syslog line.

### 6.2 Hysteresis & matching semantics (the subtle bits — flagged for review)
- **Hysteresis:** raise on `>= RaiseThreshold`, clear on `<= ClearThreshold`,
  hold state in between (standard). Requires `RaiseThreshold > ClearThreshold`;
  if a config has them inverted or equal, that should be a **commit-time
  validation warning/error** (open question §10). Junos requires raise > clear.
- **Defaults:** if the operator sets the stanza with only one threshold (or the
  zero-value sentinel), define defaults. Junos default raise=100, clear=100 is
  effectively "never" — but the current parser leaves the missing field at 0,
  which would make `clear=0` fire immediately. Must decide: treat 0 as "unset →
  default" vs literal. (open question §10).
- **Scope of `pool-utilization-alarm`:** in the config it is stored at
  `NATConfig.PoolUtilizationAlarm` — i.e. a **single global** raise/clear pair,
  not per-pool. (Junos `set security nat source pool-utilization-alarm` is global
  too.) So the same thresholds apply to **every** source pool; the alarm
  registry keys on pool name. Confirm this matches the parsed shape (it does:
  `sec.NAT.PoolUtilizationAlarm` is one struct).
- **Pool aggregation across rules:** `SourceNATPoolStatus` is per-(rule,pool). A
  pool used by multiple rules appears multiple times. Decide whether utilization
  is summed across rules per pool (likely yes — a pool is one address/port
  resource) or kept per-(rule,pool). Leaning: aggregate by pool name (sum
  UsedPorts; capacity is pool-intrinsic). (open question §10).
- **Persistent-NAT / deterministic pools:** UsedPorts semantics differ (leases
  vs translated tuples). For r1, treat `UsedPorts` uniformly; note deterministic
  pools may want block-based utilization later (follow-up).

### 6.3 `show security alarms` integration
Extend `showSecurityAlarms()` (`server_show_security_text.go:308`) to append, for
each active NAT pool alarm: `Class: NAT, Severity: Minor/Major, Description: "NAT
source pool <name> utilization <pct>% exceeds raise-threshold <R>%"`. Detail mode
adds first-seen timestamp + current pct. The handler reads the monitor's active
set (thread-safe accessor). Class/severity wording to mirror Junos.

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
- Fixing the dead `ReadNATPortCounter`/`metrics_nat.go`/CLI legacy eBPF-counter
  path (→ separate cleanup issue; #2079 must not depend on it).
- Per-pool (vs global) threshold override syntax (not in current Junos grammar
  parsed here).

---

## 7. Blast radius

- **New code:** one small monitor (Go), ~150-250 LOC + tests; one render block in
  `showSecurityAlarms`; one syslog formatter + emit call; daemon start/stop wiring.
- **Touched files (estimated):** `pkg/daemon/daemon_run.go` (start),
  `pkg/daemon/daemon.go` (field), `pkg/grpcapi/server_show_security_text.go`
  (render), new `pkg/natpoolalarm/*` (or `pkg/daemon/*`), `pkg/logging/*` (one
  formatter), docs (`docs/` NAT/alarms + module README).
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
  cap==0 (skip), missing pool in snapshot, and multi-rule aggregation. Mutation
  test: deleting the emit call must fail a test.
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
| `UsedPorts` from a multi-rule pool double-counts / under-counts | Aggregate by pool name; add a unit test for the multi-rule case |
| Alarm flap near threshold | Hysteresis (raise!=clear) + slow 10s tick; commit-warn if raise<=clear |
| `clear=0` (unset) fires/clears spuriously | Define unset→default semantics at commit (open question §10) |
| Using the dead eBPF `ReadNATPortCounter` by mistake | Plan mandates allocator snapshot; code review must confirm |
| Log spam | Emit only on transition, never per tick (enforced by design + test) |
| Deterministic/persistent pool utilization semantics off | r1 uses raw UsedPorts; note follow-up; document the limitation |

---

## 10. Open questions (for reviewers / to resolve before /engineer)

1. **Threshold validation:** add a commit-time check that `RaiseThreshold >
   ClearThreshold` and both in (0,100]? Warning or hard error? (Junos: raise >
   clear required.) Recommend: hard validation error to prevent a never-clearing
   or always-firing config.
2. **Unset-threshold semantics:** parser leaves a missing threshold at 0. Treat
   `RaiseThreshold==0` as "alarm disabled" and `ClearThreshold` default = raise-N?
   Or require both? Recommend: require both at commit (tie to Q1).
3. **Per-(rule,pool) vs per-pool aggregation** for UsedPorts. Recommend:
   aggregate by pool name (a pool is one resource).
4. **Monitor placement:** new `pkg/natpoolalarm` package vs a daemon method.
   Recommend: small injectable struct in its own package for testability.
5. **Tick interval:** 10s proposed. Acceptable, or align to the 1s status cadence
   (reading cached status either way)? Recommend 10s (alarm is not latency-critical).
6. **Severity/class wording** in `show security alarms` to best mirror Junos
   (Class NAT; Severity Minor on raise?). Cosmetic; confirm against vSRX output.
7. **Scope of UsedPorts** — is the allocator's `owner_by_translated.len()` the
   right "utilization" numerator vs a port-space percentage that accounts for the
   round-robin counter? (allocator.rs uses unbounded round-robin for *selection*
   but `owner_by_translated` is the authoritative *in-use* set — confirmed
   §2a). Recommend: UsedPorts (in-use set) is correct.

---

## 11. References (file:line, research worktree)

- Parse/store (no consumer): `pkg/config/compiler_nat.go:334-366`,
  `pkg/config/types_security.go:241,251-255`
- Live utilization source: `userspace-dp/src/nat/allocator.rs:101-143,603-614`;
  `userspace-dp/src/nat/status.rs:9-34`; `userspace-dp/src/protocol/nat.rs:100-132`
- Wire + Go status: `pkg/dataplane/userspace/protocol.go:684,932-948`;
  `pkg/dataplane/userspace/manager.go:110,393,1094,1840`
- Daemon status accessor: `pkg/daemon/daemon_forwarding_status.go:77-85`
- Existing Prometheus consumer: `pkg/api/metrics_userspace.go:403-443`
- Dead legacy eBPF counter path (do NOT use): `pkg/api/metrics_nat.go:12-54`;
  `pkg/cli/cli_show_nat.go:293-352`; `pkg/dataplane/maps_nat.go:387-401`;
  `pkg/dataplane/loader_userspace_shim.go:52,292`
- Alarm registry / render: `pkg/grpcapi/server_show_security_text.go:304-361`
- Syslog infra: `pkg/logging/syslog.go`, `pkg/logging/ringbuf.go`,
  `pkg/logging/eventbuf.go`, `pkg/daemon/daemon_system.go:24-138`
- SNMP infra (Path C only): `pkg/snmp/traps.go`, `pkg/snmp/agent.go`,
  `pkg/config/compiler_system.go:722`
- Monitor model: `pkg/ipmon` started at `pkg/daemon/daemon_run.go:463-495`
