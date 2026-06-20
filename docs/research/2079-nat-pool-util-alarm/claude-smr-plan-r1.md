# Claude SMR — Hostile Plan Review r1 — #2079

Reviewer: Claude SMR (hostile, second-opinion). Reviewing
`docs/research/2079-nat-pool-util-alarm/plan.md` r1 against worktree source.

## Verdict: PLAN-READY-WITH-NITS

The architecture is sound and the load-bearing claims hold up under independent
verification. The recommended Path B is the right altitude. Findings below are
refinements + a few open questions the plan already flags but should resolve
before /engineer. No CRITICAL findings; one MAJOR is a strengthening, not a
blocker.

---

## Independently verified (the plan is honest)

- **F-OK1 (claim "no consumer"):** Confirmed. `grep` across `pkg/ cmd/`
  (excluding `_test.go`) shows `RaiseThreshold`/`ClearThreshold` only at
  `compiler_nat.go:336-366` (parse+store) and `types_security.go:251-255` (type).
  No reader. Audit finding stands.

- **F-OK2 (live data source):** Confirmed. `SourceNATPoolStatus`
  (`protocol.go:932-948`) carries `AddressCount`, `PortLow`, `PortHigh`,
  `UsedPorts` — utilization is computable with **no new wire field**. It is
  embedded in `ProcessStatus.SourceNATPools` (`:684`), polled at 1Hz
  (`manager.go:393` statusLoop, cached at `:1094`), reachable via
  `Daemon.userspaceDataplaneStatus()` (`daemon_forwarding_status.go:77-85`). The
  cheap-sampling claim is real.

- **F-OK3 (the DEAD legacy path — this is the plan's most important pivot, and it
  is MORE correct than the plan states):** I independently verified that
  `nat_port_counters` is **never incremented per-allocation by anything in
  userspace mode**:
  - `grep -rn "nat_port_counter|NATPortCounter|port_counter" userspace-dp/src/
    userspace-xdp/src/` → **zero hits**. Neither the Rust dataplane nor the
    AF_XDP shim touches it.
  - On the Go side, the only writer is `SeedNATPortCounters`
    (`maps_nat.go:407+`), which writes a one-time **random offset** at init.
  - Therefore `ReadNATPortCounter` (`maps_nat.go:387-401`) returns only the seed
    offset summed across CPUs — it does **NOT** track live in-use ports in
    userspace mode.
  - Consequence the plan UNDERSTATES: the existing Prometheus gauge
    `xpf_nat_pool_used_ports` (`metrics_nat.go:35`) AND the CLI `show security nat
    source pool` "Ports allocated / Utilization %" (`cli_show_nat.go:328`) are
    **already reporting garbage** (the random seed) in userspace mode today. The
    plan correctly forbids using `ReadNATPortCounter` for alarms; it should
    explicitly note these two existing surfaces are already broken (strengthens
    the "use the allocator snapshot" decision and scopes a follow-up).

- **F-OK4 (render site):** `showSecurityAlarms()`
  (`server_show_security_text.go:308-361`) is the right, extensible site — it
  already iterates config-warnings + screen-counter alarms and counts/renders
  uniformly. Appending NAT pool alarms is mechanical.

- **F-OK5 (CLAUDE.md compliance):** Plan reuses the cached 1s status (no new
  control-socket request — honors the >1/s contention rule), emits only on
  transition (no per-tick `slog.Info`), zero per-packet cost. Compliant.

---

## Findings

### MAJOR

- **M1 — `show security alarms` SUMMARY mode renders nothing per-alarm; design
  must account for it.** `showSecurityAlarms` only prints alarm *bodies* in
  `detail` mode (`:316,348`); summary mode prints just a count + "run ... detail"
  (`:355-360`). So a NAT pool alarm will be invisible by name in plain `show
  security alarms` — it only bumps the count. This matches the existing screen-
  alarm behavior, so it is **consistent**, but the plan §6.3 says "append ... for
  each active NAT pool alarm: Class: NAT ..." which implies summary rendering. The
  plan must clarify it follows the existing detail-only convention (count in
  summary, body in detail), OR consciously diverge. Recommend: match existing
  convention. Not a blocker, but the §6.3 wording is misleading as written.

### MINOR

- **m1 — Resolve the unset-threshold semantics (§10 Q2) BEFORE coding, and make
  it a commit-time decision, not a monitor-time one.** With the parser leaving a
  missing field at 0, a config that sets only `raise-threshold 80` yields
  `clear=0`, so the alarm would clear the instant utilization drops to 0% — i.e.
  effectively only-on-fully-drained clear, which is *almost* fine, but a config
  with neither set (`pool-utilization-alarm;` empty, if the grammar allows the
  bare stanza) yields raise=0/clear=0 → raises immediately at 0% and never
  clears. The monitor must guard `RaiseThreshold <= 0 → feature off for safety`,
  and ideally a commit-time validator rejects raise<=clear / out-of-range. Tie Q1
  and Q2 together; pick "require both, validate raise>clear in (0,100]" — cleanest
  and Junos-faithful. The plan flags this; it just needs to land on the answer.

- **m2 — Per-pool aggregation across rules (§6.2 / §10 Q3): commit to summing
  UsedPorts by pool name AND verify capacity is not double-counted.** A pool used
  by 2 rules appears twice in `SourceNATPools`, each carrying the same
  `AddressCount/PortLow/PortHigh` (capacity is pool-intrinsic) but *different*
  `UsedPorts` partitions. Correct utilization = `sum(UsedPorts over rules) /
  capacity_once`. Naive iteration that recomputes capacity per row and compares
  per-row utilization would under-report. The plan says "leaning aggregate by
  pool" — make it a hard requirement with a dedicated unit test (plan §8 already
  lists "multi-rule aggregation" — good; just ensure capacity is taken once).

- **m3 — Deterministic / persistent-NAT pools: `UsedPorts` is not the right
  utilization numerator for them, and the plan should say so louder.** For
  deterministic pools, utilization is block-based (host→block mapping), and for
  persistent-NAT the meaningful pressure is `PersistentLeases`. r1 using raw
  `UsedPorts` uniformly is acceptable as a documented limitation, but the plan
  should explicitly EXCLUDE deterministic pools from the alarm in r1 (rather than
  silently misreport them) OR clearly document the approximation. Recommend:
  skip deterministic pools in r1, note follow-up.

### NIT

- **n1 — §6.1 "10s tick" vs §10 Q5:** the plan both proposes 10s and asks whether
  to align to 1s. Just commit to 10s in the design; it reads as indecisive.

- **n2 — Severity/class wording (§10 Q6):** cosmetic; pick Class=NAT,
  Severity=Minor on raise to mirror the screen-alarm "Major" contrast, confirm
  against a real vSRX `show security alarms` if a sample is available, else ship
  reasonable defaults. Don't block on it.

- **n3 — Add the "existing broken surfaces" note (per F-OK3) to §2c and §6.5** so
  the follow-up cleanup issue (fix `metrics_nat.go` + CLI to read the allocator
  snapshot, or remove them) is explicitly carved out of #2079's scope.

---

## On PLAN-KILL (was it wrongly rejected?)

No — the plan correctly rejects KILL. The data already exists at 1Hz; the firing
path is ~150-250 LOC of pure Go control plane with no dataplane/wire changes.
vSRX parity (a stated core goal) wants this alarm in `show security alarms` +
syslog. The cost/benefit clearly favors implementing Path B over deleting the
knob. KILL would also regress config-paste parity (operators paste working vSRX
configs containing this stanza). Rejection is justified.

## On Path B vs A vs C

Agree with Path B. Path A alone is under-parity (Junos pushes a syslog line too);
Path C's SNMP enterprise-OID work is disproportionate for a LOW-severity fix and
correctly deferred. Path B is the right altitude.

## Required before convergence
Resolve open questions Q1+Q2 (combined: require both thresholds, validate
raise>clear in (0,100] at commit), Q3 (aggregate by pool, capacity once), and
the M1 summary-vs-detail rendering convention. Add F-OK3's "existing surfaces
already broken" note. These are doc-level resolutions, not redesigns.
