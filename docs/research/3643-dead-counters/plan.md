# #3643 — per-zone `zone_counters` + `flood_counters` dead in the userspace era

**Status:** CONVERGED v2 — 3/3 reviewers agree: HIDE (§5B) is PLAN-READY;
POPULATE (§5A) is PLAN-NEEDS-MAJOR/DEFER. Recommendation: **HIDE** (with POPULATE
fully specified below as a deferred option). See §12.
**Branch:** `research/3643-dead-counters`
**Base:** origin/master @ `7c54df10c`
**Verdict target:** POPULATE (PLAN-READY / PLAN-DEFER) vs HIDE (PLAN-KILL)

---

## 1. Status

CONVERGED v2 — 3/3 hostile plan reviews (Codex + AGY + Claude SMR) ran r1 and
converged (see §12): HIDE is PLAN-READY, POPULATE is PLAN-NEEDS-MAJOR/DEFER.
This is a `/research` deliverable: it stops at PLAN-READY / PLAN-DEFER /
PLAN-KILL. No production code changes, no PR. The user proceeds via
`/engineer 3643` after picking a path (default HIDE; opt into POPULATE §5A).

## 2. Issue framing

#3643 says the per-zone traffic counters (`zone_counters`) and per-zone flood
counters (`flood_counters`) are **read** by CLI, gRPC, REST, and Prometheus but
**never written** in the userspace-dp era. The eBPF writers lived in the
#1476-deleted XDP/TC pipeline; the userspace populate campaign (#2118 per-policy,
#2501 per-session, #2460 flowexport, #2161 NAT64, #3326 host-inbound, #3343
per-screen-reason) never covered zone or flood counters. The issue frames the
symptom as "every read returns a misleading constant 0" and asks for one of:
(a) POPULATE from the userspace helper, or (b) HIDE the dead surfaces.

**This plan corrects the issue's symptom description** (see §4/§5): on current
master the reads do **not** return a silent 0 for most configs — they **error**,
because zone IDs are now stable name-hashes in `[1, 65533]` (#3075) while the
backing BPF maps are dense arrays of only `MaxZones*2 = 128` / `MaxZones = 64`
entries. A stable-hash ID ≥ 64 indexes out of bounds, the kernel array lookup
returns `ENOENT`, and the surfaces surface that as an error. The "constant 0"
only happens for the ~0.1% of zone names that happen to hash into `[1, 63]`.

**Precise per-surface current behavior (Codex r1 factual corrections applied):**
- REST `/security/zones` → **HTTP 500** for the whole endpoint on the first
  failed zone read (`pkg/api/security.go:104` sets `readErr`, then 500s).
- Prometheus → `xpf_counter_read_errors_total` bumped **once per zone** (not
  twice): `collectZoneCounters` does `ingress…if err {Add(1); continue}`, so the
  egress read is skipped (`pkg/api/metrics_counters.go:173-181`). Still a
  permanent false read-error alert, just 1×/zone/scrape.
- `show security zones` → drops the Traffic-statistics block and prints **one
  aggregate trailing warning** (`cli_show_security_zones.go:172`), not a row per
  zone.
- `show security screen ids-option statistics` (all-zones) → prints a **per-zone
  error row** ("Error reading flood counters: …", `cli_show_security_screen.go:412`
  #3344 path).
- Flood counters are surfaced by **CLI + gRPC only** — NOT REST, NOT Prometheus
  (the issue and plan v1 over-stated this). `flood_counters` REST/Prometheus
  surfaces do not exist.

So the live behavior is *worse and more confusing* than the issue states, and
the read-side is broken **independently of whether we ever source the data.**

## 3. Honest scope/value framing

The win here is **observability correctness**, not throughput. At absolute
scale:

- **Bug being fixed (mandatory, any path):** the REST `/security/zones` endpoint
  returns HTTP 500 for essentially every real config; the Prometheus
  `xpf_counter_read_errors_total` gauge (a #3345 alerting signal) is bumped
  1× per zone per scrape forever, firing a false "counter read failing" alert;
  `show security zones` drops its Traffic-statistics block + prints an aggregate
  warning; `show security screen ids-option statistics` prints an error row per
  zone.
- **Feature being weighed (the fork):** per-zone ingress/egress packet+byte
  volume and per-zone SYN/ICMP/UDP flood-event counts. This is a Junos-parity
  nice-to-have. Operators already have global counters, per-interface RX/TX
  (in `ProcessStatus.Bindings`), per-policy hit counters (#2118), and the
  aggregate per-screen-reason drop counters (#3343, includes syn/icmp/udp-flood
  ordinals). Per-zone is incremental visibility, not a missing primitive.
- **Hot-path cost of POPULATE:** at most two slot-indexed `u64` array writes per
  forwarded packet (ingress-zone + egress-zone), on the *per-worker*
  (single-threaded, non-atomic) counter block that already increments
  `rx_packets`/`forward_candidate_packets`/`screen_drops` per packet. It is not
  a new atomic or a new map lookup on the hot path — it is one more field in an
  existing per-packet accumulate.

*If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict.* (Here "perf gain" reads as "observability
value" — a PLAN-KILL means HIDE: fix the read-side to stop the 500/false-alert
and honestly mark per-zone stats "not available", sourcing nothing.)

## 4. What's already shipped / partially batched (the plan must compose with)

All citations are `git show origin/master:<path>` verified at `7c54df10c`.

1. **Stable-hash zone IDs (#3075).** `pkg/config/zoneid.go:38 StableZoneID` folds
   FNV-1a/64 into `[1, ZoneIDReservedMin-1] = [1, 65533]`. `compiler.go:164
   assignZoneIDs` uses it. The issue's claim "Zone IDs are dense 1..N
   (compiler.go:186)" is **stale** — that was the pre-#3075 sorted-positional
   scheme. This is the crux: any per-zone-keyed dense array is infeasible.
2. **The dense-array-can't-hold-stable-hash-ID lesson is already documented and
   already bit us once** — `cold_path_hist.rs` (#1635/#3075): the old 65×65 flat
   `from*65+to` table "dropped every pair with an id ≥ 65 — silently dark-ing the
   histogram for every real config"; it was replaced by a **sparse
   `HashMap<(u16,u16), u8>` slot map** (`ColdPathSlotMap`, cold_path_hist.rs:150)
   with dense slot-indexed accumulators, `inverse[slot]→(from,to)` for reporting,
   sparse wire (only nonzero slots ride), an `overflow_active` flag, and a
   `COLD_PATH_LAYOUT_VERSION`. **This is the proven POPULATE blueprint.**
3. **The read-side fix is a mechanical clone of #2255.** NAT rule counters hit the
   *identical* problem: counter IDs became a sparse key-derived hash, so
   `ReadNATRuleCounter` (maps_nat.go:366) was changed to read a **Go-side sparse
   offset map** (`natRuleCounterOffsets map[uint32]CounterValue`, loader.go:58)
   and **never index the dense array** — its own comment says "a hash id ≥
   MaxNATRuleCounters would fail that bounded Lookup." `SetNATRuleCounterOffset`
   populates it from the status poll; `ClearNATRuleCounterOffsets` clears it.
   `IncrementGlobalCounter`/`userspaceCounterOffsets` (maps_counters.go:40) is the
   same Go-side-offset pattern for globals. Zone/flood reads were simply never
   given this treatment — which is *why they still error.*
4. **The delta-push status plumbing exists.** `manager_ha.go:716
   syncBPFCountersLocked` runs every status poll, sums per-binding counters
   (`sumBindingCounters`), and pushes deltas via `IncrementGlobalCounter` +
   per-rule NAT via `SetNATRuleCounterOffset`. Adding a per-zone setter call here
   is the established shape.
5. **Per-interface RX/TX is already on the wire.** `ProcessStatus.Bindings[]`
   carries `Ifindex`, `Interface`, `RXPackets`, `RXBytes`, `TXPackets`, `TXBytes`
   (protocol.go:2211-2367). No new wire is needed to *derive* per-zone volume
   from per-interface volume (the DERIVE option, §5C).
6. **Per-zone flood state already exists inside the Rust screen module.**
   `screen/mod.rs` keeps `syn_counters` keyed by zone, #3315 per-zone
   per-dst/per-src SYN-flood sketches, and #3343 already tallies syn-flood(0)/
   icmp-flood(1)/udp-flood(2) reason drops — but only pushes the **aggregate**
   into `GlobalCtrScreen*`. The per-zone breakdown the flood surface wants is a
   subset of data the helper already holds.
7. **The per-packet zone identity is available in the forward path.**
   `metadata.ingress_zone` / `metadata.egress_zone` (u16) are read at
   bpf_map/mod.rs:251 and event_emit.rs:143; the same values feed conntrack
   publish and event emit. A hot-path per-zone increment has the key in hand.
8. **#3408/#3344/#3345** already reworked these read surfaces to "surface the
   failure, not a fake 0" — but treated the failure as *occasional*. It is
   *structural* (always fails for id ≥ 64). The plan must not regress the #3345
   "read-error signal is real" contract while removing the *false* signal.

## 5. Concrete design

The design splits into a **mandatory read-side fix (Phase 1)** shared by every
path, then the **fork** (Phase 2): where the per-zone numbers come from.

### Phase 1 — read-side sparse-map fix (mandatory regardless of the fork)

Clone the #2255 NAT pattern onto the `dataplane.Manager` (`bpfShim`), which backs
all read surfaces via method promotion (`LegacyDataPlaneAdapter`,
legacy_dataplane.go:52):

```go
// loader.go Manager struct (guarded by existing m.mu):
zoneCounterOffsets  map[uint16][2]CounterValue // [zoneID][direction] ingress/egress
floodCounterOffsets map[uint16]FloodState      // [zoneID]

// maps_counters.go — never index the dense array again:
func (m *Manager) ReadZoneCounters(zoneID uint16, direction int) (CounterValue, error) {
    m.mu.Lock(); defer m.mu.Unlock()
    return m.zoneCounterOffsets[zoneID][direction], nil // clean zero if absent
}
func (m *Manager) SetZoneCounterOffset(zoneID uint16, direction int, v CounterValue) { ... }
func (m *Manager) ClearZoneCounterOffsets() { m.zoneCounterOffsets = nil }
// maps_screen.go — same for ReadFloodCounters / SetFloodCounterOffset /
// ClearFloodCounterOffsets.
```

Wire the clears into `ClearAllCounters` / `ClearZoneCounters` /
`ClearScreenConfigs`-adjacent paths exactly as `ClearNATRuleCounterOffsets` is
wired into `ClearNATRuleCounters`. Leave the dead dense BPF maps registered (the
shim ABI mirror is shared with fixtures) but stop reading them for these two
counter families — identical to how #2255 left the dead `nat_rule_counters`
array registered but unread.

**Effect of Phase 1 alone:** OOB errors gone → REST returns 200 with clean
zeros, Prometheus stops the false read-error bump, CLI stops erroring. But the
values are honest zeros only if nothing populates them — which reintroduces the
issue's "misleading 0" complaint. Phase 1 is therefore *necessary but not
sufficient* to close #3643; it must be paired with either §5A/§5B/§5C (source
data) or §5-HIDE (remove/mark the surfaces).

### Phase 2 — the fork

#### §5A. POPULATE (full fidelity) — recommended

Mirror `ColdPathSlotMap` for single zone IDs.

- **Rust config-apply:** build a `ZoneCounterSlots { slot_of: Box<[u8; 65536]>,
  inverse: Vec<Option<u16>>, overflow_active: bool }`. **CRITICAL (Codex+AGY r1):
  the zone-id→slot resolver on the hot path MUST be a flat direct-index LUT, NOT a
  `HashMap`.** Cold-path uses a `HashMap<(u16,u16),u8>` because a zone *pair* key
  is 32-bit (4 G entries, dense-infeasible). A *single* zone id is only 16-bit, so
  a dense `[u8; 65536]` LUT (64 KB per worker; 0 = unassigned/slot-0-reserved) is
  feasible and gives `O(1)` no-hash resolution — cold-path's per-sample
  `HashMap::get` (`cold_path_hist.rs:279`, `poll_descriptor/mod.rs:2266`) would
  throttle a per-*packet* path. Assign slots to the sorted configured zone-id set
  at apply; cap at `≤255` active zones (`u8` slot, matching
  `COLD_PATH_ASSIGNABLE_SLOTS=255`); a zone past the cap sets `overflow_active`
  and its packets go uncounted (documented, same as cold-path overflow).
- **Rust hot path (per-worker, non-atomic, in the existing per-packet counter
  block):** `let s = slot_of[meta.ingress_zone as usize]; if s != 0 {
  wc.zone_pkts[s].ingress += 1; wc.zone_bytes[s].ingress += len; }` and the
  egress-slot analog. Two direct-index array reads + writes per forwarded packet
  on the block that already does `rx_packets += 1`. **No new atomic, no map
  lookup, no per-packet hash.**
- **Flood (Codex r1 correction):** the screen module holds per-zone *rate-limiter*
  state (`screen/mod.rs:153`), **not** cumulative per-zone flood-event counters —
  durable screen accounting today is global/per-reason via `record_screen_drop`
  (`afxdp/mod.rs:564`), not per-zone. So per-zone flood is **new drop-path
  accounting**, not a snapshot of existing state. Add a per-zone syn/icmp/udp
  drop tally on the `record_screen_drop` path (already off the fast path — only
  fires on a screen drop). **Recommended narrowing:** ship per-zone packets/bytes
  and mark per-zone flood "not available", leaning on the #3343 aggregate
  per-reason counters, unless per-zone flood attribution is explicitly demanded
  (halves the Rust/wire work for the lower-value half).
- **Wire (helper pre-sums across workers — Codex+SMR r1):** add ONE
  `ProcessStatus`-level sparse per-zone block (NOT per-`BindingStatus`) mirroring
  the cold-path sparse encoding: `[{zone_id, ingress_pkts, ingress_bytes,
  egress_pkts, egress_bytes[, syn, icmp, udp]}]`, only nonzero entries, layout
  version bump, `#[serde(default)]` cross-version safety, JSON round-trip test
  both sides (cold_path_status_test.go / protocol/tests.rs pattern). Pre-summing
  in the helper keeps wire cost `O(active zones)` per poll, not `O(zones ×
  bindings)`, and spares the Go side from iterating every binding's map.
- **Go status poll:** `syncBPFCountersLocked` reads the pre-summed per-zone block
  and calls `SetZoneCounterOffset` / `SetFloodCounterOffset` (absolute, overwrite
  — same as `SetNATRuleCounterOffset`, reset-safe because the helper reports
  cumulative-since-launch totals).
- **Clear semantics (MANDATORY for POPULATE — Codex+AGY r1):** clearing only the
  Go offset maps is NOT enough — the helper's cumulative totals snap back on the
  next 1 s poll. `ClearAllCounters`/`ClearZoneCounters` MUST send a new
  `clear_zone_counters` (+ flood) control-socket IPC so the helper resets its
  accumulators, exactly as `ClearNATRuleCounters`
  (`pkg/dataplane/userspace/natcounters.go`) and the policy clear
  (`policycounters.go:163`) do for their cumulative helper stores. This is a new
  control-request family + a helper reset handler, not just a Go map nil-out.
  (One-time clears only — no new >1/s control-socket caller, per the CLAUDE.md
  control-socket-contention rule.)

#### §5B. HIDE (PLAN-KILL of the feature) — the conservative fallback

Ship **only Phase 1's read-side fix**, then *remove the misleading surfaces*
rather than sourcing data:
- Drop the `xpf_zone_packets_total` / `xpf_zone_bytes_total` Prometheus metrics
  (they only ever emitted skipped/errored samples — no real data lost) and the
  per-zone flood metric.
- In CLI/gRPC/REST, either omit the per-zone Traffic-statistics / flood blocks or
  render an explicit `not available (per-zone accounting not implemented in the
  userspace dataplane)` — distinct from `0` and distinct from a read *error*.
- Keep the global + per-interface + per-policy + per-screen-reason surfaces
  (all live). Document the gap in the operator docs.
- Leave a `docs/`-recorded DEFER hook to §5A if a customer demands per-zone
  volume dashboards.

#### §5C. DERIVE (tempting middle — recommend REJECT as primary)

Since per-interface RX/TX(+bytes) is already on the wire (§4.5) and the compiler
knows zone→interface, `syncBPFCountersLocked` could aggregate per-binding RX→zone
ingress and TX→zone egress with **zero hot-path cost and zero wire change**, then
`SetZoneCounterOffset`. **Fidelity gap that kills it as the primary:** a binding
is per *physical* netdev — userspace binds VLAN units to the parent netdev
(`pkg/dataplane/userspace/interfaces.go:90`), so a single binding's RX/TX cannot
be split by the logical VLAN-unit zone. When one physical interface hosts VLAN
units in *different* zones (e.g. `ge-0-0-2.50` in one zone and `.80` in another —
a generic multi-zone-trunk topology; note the loss cluster's own `reth0.50`/`.80`
are BOTH in `wan` per `docs/ha-cluster-userspace.conf:154`, so it is NOT itself a
counterexample — use a real multi-zone trunk), DERIVE mis-attributes all of it to
one zone or fails to match the unit name. Producing *subtly wrong* per-zone
numbers is worse than an honest "not available." DERIVE is acceptable only as a
documented low-fidelity fallback for whole-interface-zone deployments, never the
shipped default.

## 6. Public API preservation

- `Manager.ReadZoneCounters(uint16, int) (CounterValue, error)` — signature
  preserved; body changes to read the Go-side offset map. All callers
  (api.go:31, cli/runtime.go:38, grpcapi/runtime.go:19, daemon/runtime_probes.go)
  unchanged.
- `Manager.ReadFloodCounters(uint16) (FloodState, error)` — preserved likewise.
- `Manager.ClearZoneCounters()` / `ClearAllCounters()` — preserved; gain an
  offset-clear like `ClearNATRuleCounters`.
- New additive: `SetZoneCounterOffset`, `SetFloodCounterOffset`,
  `ClearZoneCounterOffsets`, `ClearFloodCounterOffsets` (mirror the NAT-offset
  method family).
- Wire (§5A only): additive `#[serde(default)]` per-zone block + layout-version
  bump; no field removed/renamed. HIDE (§5B) removes Prometheus metric names
  (the only intentional surface removal).

## 7. Hidden invariants the change must preserve

- **HA symmetry (#3075) — RELAXED after Codex+SMR r1:** the *wire carries zone
  IDs*, not slot indices, and no public/cross-node surface consumes the slot as
  identity (confirmed: cold-path slots are node-local and never synced; the
  zone-counter block is `{zone_id, counters}` and the Go side maps by zone id).
  So slot assignment can be **node-local** and slot determinism is NOT an HA
  invariant. Zone IDs themselves must remain a pure function of the zone name
  (already guaranteed by `StableZoneID`/`buildZoneIDs`, zoneid.go). Sorting zone
  IDs before slot assignment is desirable only for single-node reproducibility,
  not correctness. Before shipping §5A, confirm no session-sync/config-sync path
  serializes a slot index.
- **Offset absoluteness / reset-safety:** setters overwrite with cumulative
  totals; `safeDelta` semantics do not apply to `Set*Offset` (only to
  `IncrementGlobalCounter`). On helper restart the cumulative resets to a smaller
  value and the absolute overwrite is correct — same as `SetNATRuleCounterOffset`.
- **#3345 read-error contract:** `xpf_counter_read_errors_total` must still climb
  on a *genuine* map/IPC read failure. Phase 1 removes only the *structural false*
  OOB bump; a real failure (e.g. map missing) must still register. Keep the
  `counterReadErrors.Add(1)` on any error path that survives.
- **Mutex discipline:** the offset maps share `m.mu` (already protecting
  `userspaceCounterOffsets`/`natRuleCounterOffsets`). No new lock; no logging
  under the lock (the #2285 re-entrant-slog hazard).
- **No per-packet allocation / no per-packet atomic (§5A):** the per-zone
  increment is a slot-indexed write on the per-worker block, summed at status —
  never `fetch_add` on a shared cell, never a `HashMap` lookup on the hot path
  (the slot is resolved from `metadata.ingress_zone` via the pre-built dense
  `slot_by_zone` only; the hot path writes `zone_pkts[slot]`).
- **overflow_active honesty:** a zone that overflows the slot cap must be
  observably uncounted (surface the flag), not silently merged into slot 0.
- **Fixture/parity:** the shared BPF struct sizes (`bpf/headers`) and the
  wire fixture (`protocol_wire_v1.json` / cold_path_status_test) must regen if
  the wire changes (§5A). HIDE (§5B) touches no wire.

## 8. Risk assessment

| Path | Behavioral regression | Lifetime/borrow | Perf regression | Architectural mismatch |
|------|----------------------|-----------------|-----------------|------------------------|
| **Phase 1 (read-side, all paths)** | LOW — mechanical #2255 clone; converts error→clean-zero; only behavior change is REST 200-not-500, no false alert | N/A (Go) | NONE (read-time map lookup) | LOW — identical to shipped NAT-offset design |
| **§5A POPULATE** | MED — new sparse wire + hot-path counter + new clear-IPC family + new per-zone flood drop accounting; more moving parts than v1 admitted (Codex NEEDS-MAJOR) | LOW (Rust slot arrays are fixed `[u8;65536]` LUT + `Vec` accumulators; no new borrows on hot path) | LOW — **iff** the flat `[u8;65536]` LUT is used (2 direct-index writes/pkt); a per-packet `HashMap::get` would throttle forwarding (Codex+AGY) — measure on loss cluster | LOW — clones cold_path_hist + #2255; no dead-end |
| **§5B HIDE** | LOW — removes surfaces that only ever errored; metric-name removal is the only compat note | N/A | NONE | NONE — accepts global-only, matches "observability is nice-to-have" stance |
| **§5C DERIVE** | **MED-HIGH** — mis-attributes VLAN-unit zones (wrong numbers in the project's own WAN topology) | N/A | NONE | **HIGH** — produces plausible-but-wrong per-zone data; rejected as primary |

## 9. Test plan

- **Go:** `go test ./pkg/dataplane/... ./pkg/api/... ./pkg/cli/... ./pkg/grpcapi/...`
  Add: (Phase 1) a unit test that `ReadZoneCounters`/`ReadFloodCounters` return a
  clean `(zero, nil)` for a stable-hash zone ID ≥ 64 (the current OOB case) — this
  test *fails on master* (proves the bug) and passes after; (Phase 1) a REST test
  that `/security/zones` returns 200 not 500 with a large zone ID; (Phase 1) a
  Prometheus test that `xpf_counter_read_errors_total` does **not** climb from
  zone/flood reads while still climbing on a genuine injected read error
  (guard the #3345 contract); (§5A) a status-poll test that a synthetic per-zone
  block populates `ReadZoneCounters`/`ReadFloodCounters`.
- **Rust (§5A):** `cargo test` full suite; add `ZoneCounterSlotMap` build tests
  mirroring `cold_path_hist::tests::build_assigns_slots_for_wide_stable_hash_zone_ids`
  (assert a zone ID like 40000 gets a slot and counts, not a dense-table drop);
  overflow test; wire round-trip test both sides (protocol/tests.rs +
  cold_path_status_test.go analog).
- **HA-symmetry (§5A):** the existing zone-ID symmetry test must extend to slot
  assignment determinism.
- **Smoke (loss userspace cluster, `loss:xpf-userspace-fw0/fw1`):**
  `make cluster-deploy`; re-apply CoS; 12-stream iperf3 v4+v6 to
  172.16.80.200 / 2001:559:8585:80::200 and confirm `show security zones` per-zone
  ingress/egress advance for the trust + WAN zones (§5A) or render "not available"
  (§5B); confirm REST `/security/zones` is 200 and `xpf_counter_read_errors_total`
  is flat. For §5A, capture a perf delta (throughput must stay at the ~22-23 Gbps
  baseline; the per-zone increment must not regress it).
- **test-failover (§5A only — touches wire/status the HA path reads):**
  `make test-failover` must stay 0-drop (the plan does not touch session sync,
  but the wire/layout bump rides the same status channel).

## 10. Out of scope (explicitly)

- Per-zone accounting granularity finer than the zone (per-policy already exists;
  per-session already exists #2501).
- Reviving the dense `zone_counters`/`flood_counters` BPF arrays as live maps
  (they stay registered-but-unread, like `nat_rule_counters` post-#2255).
- Per-interface counter population (`interface_counters` is separately unwritten
  in the userspace era — related but a distinct gap; note it, do not fix here).
- Filing the REST-500/false-alert as a separate bug: this plan folds it into
  #3643's Phase 1 since it shares the exact root; split only if the user prefers.
- NPTv6/NAT64-specific per-zone breakdowns.

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Is per-zone traffic accounting worth ANY new hot-path code, given global +
   per-interface + per-policy + per-screen-reason counters already exist?** If
   the answer is "no", the verdict is HIDE/PLAN-KILL and §5A never ships.
2. **Is the REST-500 / Prometheus-false-alert claim correct?** It rests on: BPF
   dense-array `Lookup(key ≥ max_entries)` returns `ENOENT`/`ErrKeyNotExist`
   (kernel `array_map_lookup_elem`). The empirical probe could not run here (no
   CAP_BPF in the research sandbox); it is corroborated by
   `constants_test.go:85` ("ifindex == MaxInterfaces is out of range for a dense
   array") and the #2255 comment ("a hash id ≥ MaxNATRuleCounters would fail that
   bounded Lookup"). **Must be smoke-verified on the cluster before Phase 1 is
   called a bug fix.** If reads actually return clean zeros (not errors), the
   severity drops to the issue's original "misleading 0" and Phase 1 shrinks.
3. **Is the ~0.1% in-range probability right, and does it matter?** `63/65533`
   per zone name; a real config essentially always has ≥1 zone with ID ≥ 64.
   Could a deployment's zone set happen to all land in `[1,63]` and mask the bug?
4. **§5A wire: sparse per-`BindingStatus` block vs one worker-summed
   `ProcessStatus` block?** Cold-path chose per-worker-then-sum. Per-binding
   inflates the wire under many-zone configs; is the sparse encoding + nonzero
   filter enough, or should the helper pre-sum across workers?
5. **§5A HA determinism:** is sorting zone IDs before slot assignment sufficient
   for both-node/cold-boot slot agreement, or does any surface read the *slot*
   (not the zone ID) cross-node such that a slot renumber breaks it? (Cold-path
   slots are node-local and never synced — confirm zone-counter slots can be too.)
6. **Should the flood surface simply lean on #3343's aggregate per-reason global
   counters** and mark per-zone flood "not available", even under §5A — i.e. is
   per-*zone* flood attribution worth the sparse-wire block when the aggregate
   already exists?
7. **Is DERIVE (§5C) actually disqualified, or is whole-interface-zone attribution
   "good enough" for a first cut** with a documented VLAN-unit caveat, given it
   needs zero Rust/wire change? (I argue no — wrong numbers > honest gap — but
   invite the counter-argument.)
8. **Metric removal (§5B):** does dropping `xpf_zone_packets_total`/`_bytes_total`
   break any committed dashboard/alert contract, or are they safe to remove since
   they never emitted real data?

---

## 12. Converged reviewer verdicts (r1) + recommendation

All three reviewers ran hostile r1 against `87749ce81`. They **converged in one
round**: the read-side fix + HIDE path is ready; the POPULATE path is
NEEDS-MAJOR. v2 above folds every finding.

| Reviewer | Verdict | Core finding |
|----------|---------|--------------|
| **Codex** (`task-mr1zpu51-cyf9rg`) | **PLAN-NEEDS-MAJOR** (POPULATE); read-side fix approve-after-corrections; "HIDE is a defensible product verdict" | Hot-path cost unproven (cold-path does a per-sample `HashMap::get`); flood is NEW drop accounting not a snapshot; clear-IPC missing; several read-surface facts overstated (Prometheus 1× not 2×, flood not on REST/Prom, zones-CLI = 1 warning); DERIVE topology example wrong (reth0.50/.80 both in `wan`) |
| **AGY** (`adversarial-review-mr1zq1au-fxheaq`) | **PLAN-NEEDS-MAJOR** (POPULATE) / **PLAN-READY** (HIDE); **recommends HIDE** | Same hot-path finding — must use a flat `[u8;65536]` LUT, not a HashMap; missing `clear_zone_counters` IPC; per-zone largely redundant with per-policy + per-interface counters → HIDE resolves the 500/alert-storm with zero complexity |
| **Claude SMR** (`claude-smr-plan-r1.md`) | **PLAN-NEEDS-MINOR → conditionally PLAN-READY** | OOB-error linchpin is corroborated (maps_nat.go:366 maintainer comment) but unverified in-sandbox → must cluster-verify before calling Phase 1 a "bug fix"; Phase 1 alone regresses to the issue's "misleading 0" → must pair with data or explicit "not available"; reframe to the narrow question "is VLAN-unit-granular per-zone volume wanted?"; pre-sum wire; node-local slots |

**Points of unanimous agreement:**
1. The read-side breakage is real (stable-hash IDs OOB the dense arrays →
   REST 500 + Prometheus false alert + CLI errors). All three independently
   confirmed the mechanism against origin/master. **Still must be smoke-verified
   on the cluster** before Phase 1 is called a bug fix (SMR F1 — no CAP_BPF in
   the research sandbox to run the empirical probe).
2. The read-side fix is a low-risk mechanical #2255 clone.
3. POPULATE, if pursued, MUST use a flat direct-index `[u8;65536]` slot LUT (no
   per-packet hash), a new `clear_zone_counters` IPC, and new per-zone flood drop
   accounting — it is NEEDS-MAJOR as spec'd in v1, now specified in v2.
4. HIDE (Phase 1 read-side fix + explicit "not available" + drop the dead
   Prometheus per-zone metrics) is PLAN-READY and low-risk.
5. Per-zone flood is the lowest-value half → lean on the #3343 aggregate.

### Recommendation: **HIDE (PLAN-READY) — i.e. PLAN-KILL the POPULATE feature for now**

Ship the mandatory read-side #2255-clone fix (stops the live REST-500 /
Prometheus-false-alert / CLI-errors) and **render the per-zone traffic + flood
surfaces as an explicit "not available (per-zone accounting not implemented in
the userspace dataplane)" — never a bare 0 — and drop the always-erroring
`xpf_zone_packets_total`/`xpf_zone_bytes_total` Prometheus metrics.** Rationale
(2 of 3 reviewers, incl. AGY explicitly): per-zone volume is largely redundant
with the already-live global + per-interface (`Bindings[].RX/TX{Packets,Bytes}`)
+ per-policy (#2118) + per-screen-reason (#3343) counters; the only *unique*
value POPULATE adds is VLAN-unit-granular per-zone volume, and no operator demand
for that is on record. HIDE resolves the live bug with zero hot-path cost and
minimal risk.

**POPULATE (§5A) is DEFERRED, not deleted** — it is now fully specified (flat LUT
+ pre-summed sparse wire + `clear_zone_counters` IPC + per-zone flood drop
accounting) and can be picked up via `/engineer 3643` if per-zone / VLAN-unit
volume dashboards are demanded. DERIVE (§5C) stays rejected as a primary.

**Verdict:** PLAN-READY for HIDE + PLAN-DEFER for POPULATE. Label
`plan-deferred-research`; keep the issue OPEN (a live read-side bug fix is still
owed — this is not works-as-intended). Await manual approval — type
`/engineer 3643` to implement (default: HIDE + read-side fix; opt into POPULATE
§5A if per-zone volume is wanted). The Phase-1 read-side fix MUST be
cluster-smoke-verified (REST 200, flat `xpf_counter_read_errors_total`) as part
of `/engineer`.
