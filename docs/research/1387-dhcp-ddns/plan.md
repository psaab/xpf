# #1387 DHCP server: dynamic DNS updates and stale lease cleanup — residual research plan

- **Revision:** r2 (converged — SMR r1 folds applied: MAJOR-1 disabled-omit
  unconditional, MAJOR-2 dual compile-site as binding R4, MAJOR-3 timers
  Min(1)/caps Min(0), MINOR-2 honest value framing)
- **Issue:** #1387 (label: `plan-deferred-lab`)
- **Branch:** `research/1387-dhcp-ddns-residual`
- **Mode:** `/research` — PLAN ONLY. No production source touched, no PR.
- **Scope of THIS doc:** the *residual* work on #1387 after Inc-1 (#2043)
  and Inc-2 (#2066) already shipped the DDNS control plane. The two
  things this re-examination resolves: (1) is the remaining DDNS work
  (kea-d2 backend / live-lab) now driveable? (2) the **stale lease
  cleanup half**, which the issue's "Architecture plan" never broke out
  into an increment and which is the genuinely-unshipped, lab-free slice.

---

## 1. Status

**PLAN-READY for the stale-lease-cleanup slice (Path S).**
**PLAN-DEFERRED (terminal) for the live-lab DDNS validation residue.**
**PLAN-KILL (do not build now) for the kea-d2 alternate DDNS backend.**

The DDNS half of #1387 is *substantially shipped on origin/master*:

- **Inc-1 (PR #2043, `9979a89a0`)** — config model (`DHCPDynamicDNSConfig`),
  state-aware lease parser, `DNSUpdater` interface, reconciler core
  (`reconcileOnceLocked`), never-delete-non-owned ownership store. Fully
  unit-tested with a fake updater.
- **Inc-2 (PR #2066, `ec46efbc7`)** — live RFC 2136 / TSIG backend
  (`ddns_rfc2136.go`), the always-on daemon reconcile loop
  (`daemon_ddns.go`), the node-level HA single-writer gate, the
  `xpf_dhcp_ddns_*` Prometheus metrics, and `show system services
  dhcp-server dynamic-dns [detail]`. Validated with an in-process
  `miekg/dns` server (real UDP/TCP + TSIG) and `make test-failover`
  14/14 @ 22.9 Gbps.

So the prompt's framing ("re-examine whether *Kea DDNS config
generation* is now driveable") is answered: **DDNS was implemented, but
NOT via Kea D2 config generation.** The shipped design is *direct RFC
2136 from xpfd* (issue Open-Question 1, "Path A"), chosen because it
gives xpf the ownership-state cleanup boundary and CI-testability the
issue's Phase 1 demanded. The Kea-D2 path the prompt asks about is a
**reserved enum value** (`backend kea-d2`) with a WARN-only validator
and no runtime — and this plan recommends it stays that way (§3, §10).

What is left, in priority order:

1. **Stale lease cleanup (Path S)** — Kea `expired-leases-processing`
   config-gen + a small xpf-native config subtree. **Fully
   implementable + unit-testable now, zero lab.** This is the
   recommended slice to engineer.
2. **Live DDNS lab validation** — Kea→real-DNS end-to-end + DDNS-over-
   failover. Needs a DNS-server fixture absent from the loss/incus
   cluster. **Terminal PLAN-DEFERRED** (a venue problem, not a design
   problem).
3. **kea-d2 backend** — demand-gated, redundant with the shipped
   rfc2136 path. **PLAN-KILL** until an operator needs it.

---

## 2. Framing

The issue title bundles two independent features under one number:

- **"dynamic DNS updates"** — publish/withdraw A/AAAA/PTR for leases.
  **DONE** (Inc-1 + Inc-2). Only live-lab proof + an unused alt backend
  remain.
- **"stale lease cleanup"** — make Kea actually *remove* expired/
  released/declined/reclaimed lease ROWS from the memfile (lease
  database), instead of letting them accumulate until the next
  lease-file-cleanup (LFC) compaction. **NOT DONE.**

These two are often conflated because they share the word "stale," but
they are different layers:

- DDNS stale-record cleanup (DNS layer) — already handled by the
  reconciler's expire/reassign Pass 1 (`ddns.go:413-447`): a lease that
  leaves the active set gets its A/AAAA/PTR withdrawn.
- DHCP lease-database stale-row cleanup (Kea memfile layer) — NOT
  handled. xpf renders Kea with `lease-database: {type: memfile}` and
  **no `expired-leases-processing` block** (`dhcpserver.go:750-765`,
  `860-872`). Kea's reclamation defaults are conservative; without
  tuning, expired leases linger in `kea-leases4.csv` /
  `kea-leases6.csv` as appended rows. The `show dhcp-server` display
  parser hides them (`parseLeaseCSV` state+expire filter,
  `dhcpserver.go:528-550`, #2085), but they are physically present —
  they bloat the memfile, slow startup re-load, and (the operator-
  visible symptom the issue actually cares about) an expired lease's
  identity is not released for *reuse-accounting* until reclamation
  runs.

The honest engineering read: **Path S is the small, correct, lab-free
residual that closes the second half of the issue title.** Everything
DDNS-shaped is either shipped or venue-blocked.

---

## 3. Scope & value

### In scope (Path S — recommended)

A config subtree under `system services dhcp-local-server` and
`dhcpv6-local-server` controlling Kea expired-lease reclamation, plus
its render into the generated Kea config:

```
set system services dhcp-local-server expired-leases-processing enable
set system services dhcp-local-server expired-leases-processing reclaim-timer 10
set system services dhcp-local-server expired-leases-processing flush-timer 25
set system services dhcp-local-server expired-leases-processing hold-time 600
set system services dhcp-local-server expired-leases-processing max-leases 100
```

Render target (new sibling key in the `Dhcp4`/`Dhcp6` map):

```json
"expired-leases-processing": {
  "reclaim-timer-wait-time": 10,
  "flush-reclaimed-timer-wait-time": 25,
  "hold-reclaimed-time": 600,
  "max-reclaim-leases": 100,
  "max-reclaim-time": 250,
  "unwarned-reclaim-cycles": 5
}
```

**Value (honest framing, SMR MINOR-2):** closes the second half of the
issue title with a small, fully-CI-testable change. The PRIMARY benefit
is **memfile hygiene** (bounds append-log growth + startup re-load cost)
and **correct Kea internal reclamation/reuse** of expired addresses. It
does NOT fix a visible `show dhcp-server` defect — #2085 already filters
stale rows at display, so the display is truthful today; Path S makes the
*source* truthful by actually removing the rows Kea would otherwise keep.
Opt-in: an absent (or disabled) block renders byte-identical to today.

### Out of scope (this doc)

- The DDNS feature itself (shipped).
- Live Kea→DNS lab validation (terminal PLAN-DEFERRED, §10).
- The kea-d2 backend (PLAN-KILL, §10): it would *duplicate* the
  rfc2136 path with no operator-visible advantage in the current
  image (kea-dhcp-ddns/D2 is not in `bake.py`; pulling it in adds a
  daemon, a second config file, a second service lifecycle, and a
  second HA-ownership story — for a feature the shipped backend
  already delivers). Keep the reserved enum + WARN.
- Per-pool override of reclamation knobs. Kea's
  `expired-leases-processing` is a **global** (per-Dhcp4/Dhcp6) block,
  not per-subnet — so there is nothing to render per-pool. Server-level
  only.

---

## 4. What's already shipped (precise inventory)

Read these before engineering Path S; Path S slots cleanly beside them.

| Concern | File / symbol | State |
|---|---|---|
| DDNS config model | `pkg/config/types_system.go:850-935` `DHCPDynamicDNSConfig` | shipped |
| DDNS schema | `pkg/config/schema_system.go:556-626` `dhcpDynamicDNSSchema()` | shipped |
| DDNS compiler + WARN validator | `pkg/config/compiler_dhcp_ddns_test.go`, `validateDDNSBackendWarnings` | shipped |
| DDNS reconciler core | `pkg/dhcpserver/ddns.go` `reconcileOnceLocked` | shipped |
| DDNS lease parser (state-aware) | `pkg/dhcpserver/ddns_leases.go` `parseActiveLeases{4,6}` | shipped |
| DDNS hostname normalize | `pkg/dhcpserver/ddns_hostname.go` `deriveFQDN` | shipped |
| DDNS ownership store | `pkg/dhcpserver/ddns_state.go` `ddnsState` | shipped |
| Live RFC 2136 backend | `pkg/dhcpserver/ddns_rfc2136.go` `newRFC2136Updater` | shipped |
| Daemon loop + HA gate | `pkg/daemon/daemon_ddns.go` `runDDNSReconcileLoop`, `ddnsWriterGateOpen` | shipped |
| Metrics | `pkg/api/metrics_system.go` `collectDDNSMetrics` | shipped |
| `show ... dynamic-dns` | cmdtree + grpc + cli | shipped |

**Kea render (the Path S touch points):**

- `Manager.generateKea4Config` — `dhcpserver.go:660-765`. Top-level
  `Dhcp4` map at `:750-760` has keys `interfaces-config`,
  `lease-database`, `valid-lifetime`, `subnet4`. **No
  `expired-leases-processing`.**
- `Manager.generateKea6Config` — `dhcpserver.go:767-875`. Same shape
  for `Dhcp6` at `:860-869`.
- The `valid-lifetime: 86400` server default is hardcoded
  (`:758`, `:868`); per-pool `LeaseTime` overrides it per subnet
  (`:715-717`, `:828-830`). Path S does NOT touch lease-time; it
  controls reclamation of *already-expired* leases. (See §8 invariant
  H4 for why these are independent knobs.)
- `writeKeaConfig` — `dhcpserver.go:898-910`, `AtomicGeneratedConfig`
  class, `fsatomic.WriteFileAtomic` (no fsync). Path S adds one map
  key; no new write path.

**Confirmed absent (repo-wide grep):** `expired-leases-processing`,
`reclaim-timer-wait-time`, `flush-reclaimed-timer-wait-time`,
`hold-reclaimed-time`, `max-reclaim-leases`, `unwarned-reclaim-cycles`
— **zero** matches in any `.go` file (the only hit is a comment about
LFC at `dhcpserver.go:422`). No config-model field, no schema leaf, no
render.

---

## 5. Concrete design (Path S)

### 5.1 Config model

Add a server-level (not pool-level) reclamation block to
`DHCPLocalServerConfig` in `pkg/config/types_system.go`. The block
lives on each family's `DHCPLocalServerConfig` so v4 and v6 can be
tuned independently (Kea renders the block per `Dhcp4`/`Dhcp6`):

```go
// DHCPLocalServerConfig holds per-group DHCP server settings.
type DHCPLocalServerConfig struct {
	Groups map[string]*DHCPServerGroup
	// ExpiredLeases is the opt-in Kea reclamation policy (#1387 stale-
	// lease-cleanup slice). nil == today's behaviour byte-for-byte: no
	// expired-leases-processing block is rendered and Kea uses its
	// built-in defaults. The block is GLOBAL to the family (Kea has no
	// per-subnet reclamation), so it sits here, not on DHCPPool.
	ExpiredLeases *DHCPExpiredLeasesConfig
}

// DHCPExpiredLeasesConfig maps to Kea's expired-leases-processing block.
// Field units/semantics are Kea-native (the operator types Kea numbers);
// see https://kea.readthedocs.io for the authoritative meaning. Zero on
// an unset numeric field means "omit -> Kea default", so an operator can
// flip `enable` on and tune one knob without pinning the rest.
type DHCPExpiredLeasesConfig struct {
	// Enabled gates rendering of the whole block. A block that parses
	// but never sets enable still renders nothing (explicit opt-in,
	// mirrors DDNS Enabled).
	Enabled bool
	// ReclaimTimerWait is seconds between reclamation cycles
	// (reclaim-timer-wait-time). 0 -> omit.
	ReclaimTimerWait int
	// FlushReclaimedTimerWait is seconds between flush passes that
	// remove reclaimed leases past hold-time
	// (flush-reclaimed-timer-wait-time). 0 -> omit.
	FlushReclaimedTimerWait int
	// HoldReclaimedTime is seconds a reclaimed lease is retained before
	// physical removal (hold-reclaimed-time). 0 -> omit. (Kea keeps a
	// reclaimed lease this long so a renewing client reclaims its own
	// address; relevant to the "same address reassigned" DDNS case.)
	HoldReclaimedTime int
	// MaxReclaimLeases caps leases reclaimed per cycle (max-reclaim-
	// leases; 0 in Kea means "no limit", so we DISTINGUISH unset from 0
	// — see §8 H2). Use a *int or a sentinel; plan picks explicit
	// "set/unset" tracking, NOT a bare 0 == default).
	MaxReclaimLeases int
	maxReclaimSet    bool // true when MaxReclaimLeases was explicitly set
	// MaxReclaimTime caps milliseconds spent reclaiming per cycle
	// (max-reclaim-time). 0 -> omit.
	MaxReclaimTime int
	// UnwarnedReclaimCycles is consecutive cycles hitting the cap before
	// Kea warns (unwarned-reclaim-cycles). 0 -> omit.
	UnwarnedReclaimCycles int
}
```

> Design note on the `0`-is-meaningful knob: Kea's `max-reclaim-leases:
> 0` means *unlimited*, which is a DIFFERENT desired state from "omit
> the key and inherit Kea's default of 100." The plan tracks an explicit
> `maxReclaimSet bool` (or makes the field `*int`) so the operator can
> say `max-leases 0` (unlimited) distinctly from not configuring it. See
> §8 H2. Codex r1 must confirm which Kea knobs have a meaningful 0 — the
> conservative answer is to apply the same set/unset discipline to every
> numeric field, but the plan only *needs* it where 0 is a valid Kea
> value with non-default meaning (verify against Kea docs at engineer
> time; `max-reclaim-leases` and `max-reclaim-time` are the candidates).

### 5.2 Schema (setSchema)

Add an `expired-leases-processing` child to BOTH `dhcp-local-server`
and `dhcpv6-local-server` in `schema_system.go:329-344`, via a shared
factory (same pattern as `dhcpDynamicDNSSchema()` / `dhcpStaticBindingSchema()`
— returned fresh per call so the two parents do not share a mutable
map):

```go
func dhcpExpiredLeasesSchema() *schemaNode {
	return &schemaNode{desc: "Kea expired-lease reclamation policy (#1387)", children: map[string]*schemaNode{
		"enable": {desc: "Enable expired-lease reclamation tuning", children: nil},
		// SMR MAJOR-3: the three TIMERS use Min(1), NOT Min(0). Some Kea
		// versions reject a *-timer-wait-time of 0, and a rejected value
		// would take DHCP DOWN on the fail-closed restart (R3). Min(1) is
		// the safe default until Kea 3.0.3's acceptance of 0 is verified;
		// 0=unlimited semantics apply only to the CAP knobs below.
		"reclaim-timer": {
			desc: "Seconds between reclamation cycles (reclaim-timer-wait-time)",
			args: 1, valueType: ValueInteger,
			valueDesc: "Seconds (>= 1)", valueExamples: []string{"10"},
			validator: ValidateIntegerMin(1), children: nil,
		},
		"flush-timer": {
			desc: "Seconds between reclaimed-lease flush passes (flush-reclaimed-timer-wait-time)",
			args: 1, valueType: ValueInteger,
			valueDesc: "Seconds (>= 1)", valueExamples: []string{"25"},
			validator: ValidateIntegerMin(1), children: nil,
		},
		"hold-time": {
			desc: "Seconds a reclaimed lease is held before removal (hold-reclaimed-time)",
			args: 1, valueType: ValueInteger,
			valueDesc: "Seconds (>= 1)", valueExamples: []string{"600"},
			validator: ValidateIntegerMin(1), children: nil,
		},
		"max-leases": {
			desc: "Maximum leases reclaimed per cycle, 0 = unlimited (max-reclaim-leases)",
			args: 1, valueType: ValueInteger,
			valueDesc: "Leases per cycle (>= 0; 0 = unlimited)", valueExamples: []string{"100", "0"},
			validator: ValidateIntegerMin(0), children: nil,
		},
		"max-time": {
			desc: "Max milliseconds spent reclaiming per cycle, 0 = unlimited (max-reclaim-time)",
			args: 1, valueType: ValueInteger,
			valueDesc: "Milliseconds (>= 0; 0 = unlimited)", valueExamples: []string{"250"},
			validator: ValidateIntegerMin(0), children: nil,
		},
		"unwarned-cycles": {
			desc: "Consecutive capped cycles before Kea warns (unwarned-reclaim-cycles)",
			args: 1, valueType: ValueInteger,
			valueDesc: "Cycles (>= 0)", valueExamples: []string{"5"},
			validator: ValidateIntegerMin(0), children: nil,
		},
	}}
}
```

Wire into both parents:

```go
"dhcp-local-server": {desc: "DHCP local server", children: map[string]*schemaNode{
	"group":          { ... existing ... },
	"dynamic-dns":    dhcpDynamicDNSSchema(),
	"expired-leases-processing": dhcpExpiredLeasesSchema(),  // NEW
}},
// same NEW child under dhcpv6-local-server
```

Schema-leaf discipline (docs/config-schema.md): every node carries
`desc:`; numeric leaves are typed with `ValidateIntegerMin`. The
runtime bound is "Kea accepts it" — Kea has no documented hard upper
bound on these timers, so min-only validation is correct (no schema-only
cap, per the config-schema.md range policy). Floors (SMR MAJOR-3,
fail-safe default): the three TIMERS (reclaim/flush/hold) are
`ValidateIntegerMin(1)` because a 0 a Kea version rejects would take DHCP
down on the fail-closed restart (R3); the two CAP knobs (`max-leases`,
`max-time`) are `Min(0)` because Kea documents 0 = unlimited there;
`unwarned-cycles` is `Min(0)`. Exact Kea 3.0.3 acceptance of every value
is a binding engineer-time verification (Open Q2) before the floors are
finalized; a value Kea rejects gets a commit WARN/validator so a bad
commit never silently breaks the restart.

### 5.3 Compiler

`pkg/config/compiler_services.go` (or wherever the DHCP-server compiler
lives — confirm: the DDNS block compiles in `compiler.go` /
`compiler_dhcp_ddns*`). Add a `compileDHCPExpiredLeases` that reads the
`expired-leases-processing` node (both hierarchical and flat-set AST
shapes — the dual-AST rule) into `DHCPExpiredLeasesConfig`, attaching it
to the relevant family's `DHCPLocalServerConfig`. Set `maxReclaimSet`
when `max-leases` appears in the tree. Mirror the DDNS block's compile
sites exactly so the strict + lenient paths both handle it.

### 5.4 Kea render

Add a renderer helper and call it from both generate functions:

```go
// keaExpiredLeasesMap renders the expired-leases-processing block, or
// nil when the block is absent OR disabled (so the caller omits the key
// entirely and the rendered config is BYTE-IDENTICAL to today — H1, the
// cardinal compatibility invariant; SMR MAJOR-1 made the disabled-omit
// unconditional). Each numeric field is emitted only when set, so an
// operator can tune one knob without pinning the rest to a value we
// invented.
func keaExpiredLeasesMap(c *config.DHCPExpiredLeasesConfig) map[string]any {
	if c == nil || !c.Enabled {
		// Unconditional omit. nil OR Enabled==false ⇒ no key ⇒ H1.
		return nil
	}
	m := map[string]any{}
	if c.ReclaimTimerWait > 0 {
		m["reclaim-timer-wait-time"] = c.ReclaimTimerWait
	}
	if c.FlushReclaimedTimerWait > 0 {
		m["flush-reclaimed-timer-wait-time"] = c.FlushReclaimedTimerWait
	}
	if c.HoldReclaimedTime > 0 {
		m["hold-reclaimed-time"] = c.HoldReclaimedTime
	}
	if c.maxReclaimSet {
		m["max-reclaim-leases"] = c.MaxReclaimLeases // 0 == unlimited, intentional
	}
	if c.MaxReclaimTime > 0 {
		m["max-reclaim-time"] = c.MaxReclaimTime
	}
	if c.UnwarnedReclaimCycles > 0 {
		m["unwarned-reclaim-cycles"] = c.UnwarnedReclaimCycles
	}
	// SMR MAJOR-1 scope: this empty-{} question applies ONLY to the
	// ENABLED-with-no-knobs state reached here (Enabled==true, every
	// numeric unset) — it does NOT touch H1, which the disabled/nil omit
	// above already guarantees. Open Q1 decides empty-{} vs omit for THIS
	// state alone (Kea reads {} as "block with defaults," behaviourally
	// ~= absent; emitting {} lets the operator see the feature is on in
	// the rendered config). Confirm Kea does not warn on an empty block.
	return m
}
```

Call site (4-config), in `generateKea4Config` before building `dhcp4`:

```go
dhcp4 := map[string]any{
	"interfaces-config": ...,
	"lease-database":    ...,
	"valid-lifetime":    86400,
	"subnet4":           subnets,
}
if elp := keaExpiredLeasesMap(cfg.DHCPLocalServer.ExpiredLeases); elp != nil {
	dhcp4["expired-leases-processing"] = elp
}
m.addLeaseSyncStanza(dhcp4, 4)
```

Symmetric for `generateKea6Config` reading `cfg.DHCPv6LocalServer.ExpiredLeases`.

### 5.5 README + docs

Update `pkg/dhcpserver/README.md` with an "Expired-lease reclamation
(#1387, stale-lease-cleanup slice)" section: what the block renders,
the global-not-per-pool constraint, the 0-is-unlimited gotcha, and the
relationship to the (separate) DDNS stale-record cleanup. Per CLAUDE.md
docs-as-contract rule this ships in the same PR.

---

## 6. Multiple path options

| Path | What | Verdict |
|---|---|---|
| **S — stale-lease-cleanup config-gen** (recommended) | `expired-leases-processing` model + schema + compiler + render + README. Lab-free, CI-tested. | **PLAN-READY, engineer now.** |
| D2 — kea-d2 alternate DDNS backend | Wire `backend kea-d2`: render `dhcp-ddns` + a `kea-dhcp-ddns.conf` (D2) + manage the `kea-dhcp-ddns` service + a second HA-ownership story. | **PLAN-KILL.** Duplicates the shipped rfc2136 path; D2 not in `bake.py`; large blast radius (new daemon, new service lifecycle, dueling-writer HA story) for zero new operator capability. Reserved enum + WARN stays. |
| L — live DDNS lab validation | Stand up a throwaway BIND/Knot + TSIG fixture in the cluster; `dig`-verify add/expire/reassign + DDNS-over-failover. | **PLAN-DEFERRED (terminal).** Pure venue gap; design is done + CI-proven. Reopen when a DNS fixture venue exists. |
| S+ — per-pool reclamation | Per-subnet reclamation knobs. | **Rejected.** Kea reclamation is global per family; nothing to render per pool. |

Recommendation: **engineer Path S only.** It is the smallest change
that closes the open half of the issue title, has no lab dependency,
and is independent of the deferred/killed DDNS residue.

---

## 7. Public API preservation

- **No protobuf change.** Path S is config-render-only; no new gRPC
  field, no wire message. (DDNS already added its own; this rides
  none.)
- **No metrics change.** Reclamation is Kea-internal; xpf does not
  observe per-reclamation counters (it could later read Kea's
  `statistic-get` over the control socket, but that is out of scope and
  would need the lease-sync control socket the #2239 path conditionally
  enables — explicitly NOT a Path S dependency).
- **CLI completion** gains the new `expired-leases-processing` subtree
  on both families automatically (setSchema is the SSOT, §5.2). No
  cmdtree change (config-mode grammar lives in setSchema).
- **Stored-config compatibility:** additive nil-default field; a config
  without the block compiles and renders byte-identical to today
  (`TestLoad_ToleratesStored*` discipline). A config WITH the block
  must still load on the lenient path (boot safety) — the compiler adds
  it on both strict and lenient sites.
- **Backward render:** `keaExpiredLeasesMap` returns nil for
  nil/disabled, so the omit path is byte-identical to the current
  `generateKea{4,6}Config` output. A golden test pins this.

---

## 8. Hidden invariants

- **H1 — opt-in, byte-identical when off.** nil/disabled block ⇒ the
  rendered Kea config is byte-for-byte the current output. Pinned by a
  golden render test (disabled vs absent vs today). This is the cardinal
  compatibility invariant.
- **H2 — 0 is a meaningful Kea value for the cap knobs.**
  `max-reclaim-leases: 0` (and likely `max-reclaim-time: 0`) means
  *unlimited* in Kea, which differs from "omit ⇒ default." The model
  MUST distinguish set-to-0 from unset (the `maxReclaimSet` bool or
  `*int`). A naive `if x > 0` render would make `max-leases 0`
  un-expressible. Test: `max-leases 0` renders `"max-reclaim-leases":
  0`; not configuring it omits the key.
- **H3 — global per family, not per pool.** The block attaches to
  `DHCPLocalServerConfig` (one per family), never `DHCPPool`. Rendering
  per-subnet would be invalid Kea. Schema places it under
  `dhcp-local-server` / `dhcpv6-local-server`, not under `group`/`pool`.
- **H4 — reclamation is orthogonal to lease-time.** `valid-lifetime`
  (`dhcpserver.go:758/868`) and per-pool `LeaseTime` set how long a
  lease is VALID; `expired-leases-processing` sets how aggressively Kea
  REMOVES leases that have ALREADY expired. Path S must not touch
  lease-time. A reviewer conflating the two is the likeliest design
  error; the README section calls it out explicitly.
- **H5 — render-only, no service-lifecycle change.** The reclamation
  block is read by Kea on (re)start/reconfigure exactly like every other
  generated key. It rides the existing `Apply` /
  `ApplyClusterCommit` / `ApplyAsync` restart path (`dhcpserver.go:239-284`).
  No new `systemctl` call, no D2/extra daemon. HA-neutral (it is in the
  MASTER-filtered config each node already renders, so it is correct on
  whichever node serves a given RG).
- **H6 — dual-AST compile.** The compiler must read the block from BOTH
  the hierarchical (`expired-leases-processing { reclaim-timer 10; }`)
  and flat-set (`set ... expired-leases-processing reclaim-timer 10`)
  AST shapes (the project's standing parser gotcha). Test both via
  `ParseSetCommand()` + `tree.SetPath()` (never `NewParser()` for
  flat-set) AND a hierarchical parse.
- **H7 — lenient-load never blackholes a node.** A node that committed
  the block, then the daemon downgrades to a Kea/xpf that range-tightens
  it, must still LOAD (warn, not reject) on `Store.Load`/`SyncApply`.
  Min-only validators + lenient compile satisfy this.

---

## 9. Risk table

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| R1 | Naive `>0` render makes `max-leases 0` (unlimited) un-expressible | Med | `maxReclaimSet`/`*int` set-vs-unset tracking; explicit test (H2) |
| R2 | Block rendered per-pool ⇒ invalid Kea config ⇒ Kea won't start ⇒ DHCP down | High | Model attaches to family-level config only (H3); golden render test; the existing fail-closed Apply surfaces a Kea restart failure at commit |
| R3 | A timer value Kea rejects (e.g. 0 where Kea wants >=1) ⇒ Kea reconfigure fails ⇒ DHCP outage on commit | High | Verify Kea's accepted ranges at engineer time; add commit WARN/validator for any value Kea rejects; the fail-closed `Apply` (`dhcpserver.go:211-284`) returns the restart error so a bad commit is surfaced, not silently broken |
| R4 | Stored-config / HA-config-sync regression: the block compiled at the STRICT site only ⇒ a peer-synced or stored config with the block warn-rejects on the lenient `Store.Load`/`SyncApply` path (the #1799 / #1796-#1797 flat-set-compile-empty class) | Med→High | SMR MAJOR-2: the engineer MUST add `compileDHCPExpiredLeases` at BOTH the strict and lenient DHCP-server compile sites (mirror the DDNS/static-binding precedent), confirmed in the Codex plan-review BEFORE code; lenient-compile warn-not-reject (H7); pinned by `TestLoad_ToleratesStored*` |
| R5 | Operator confuses reclamation with lease-time and shortens leases | Low | README H4 callout; distinct keyword namespace (`expired-leases-processing` vs `pool ... lease-time`) |
| R6 | Render drift: a future Kea renames a knob | Low | Keys are Kea-native strings in one helper; a Kea version bump is caught by the live lab (deferred) or by a Kea-start failure at deploy |
| R7 | Scope creep into reading Kea reclamation stats (needs control socket) | Low | Explicitly out of scope (§7); no control-socket dependency |

No HA / VRRP / session-sync / fabric code is touched, so the
`make test-failover` mandate does not strictly apply to Path S — but a
cluster deploy + `iperf3` smoke + a DHCP-server lease cycle is still
the standard "any change" validation lane. The block is in the
MASTER-filtered config so it is HA-neutral by construction.

---

## 10. Test plan

**Unit (the bulk — fully CI, no lab):**

- Render golden: disabled/nil ⇒ Kea config byte-identical to current
  (the cardinal H1 test).
- Render: enabled + each knob set ⇒ exact `expired-leases-processing`
  JSON for v4 and v6.
- Render: `max-leases 0` ⇒ `"max-reclaim-leases": 0` present;
  not-set ⇒ key omitted (H2).
- Render: enabled + no knobs ⇒ documented empty-`{}`-vs-omit choice
  (whichever Codex/Kea-docs confirm).
- Compile dual-AST: hierarchical and flat-set both populate the model
  identically (H6) — flat-set via `ParseSetCommand`+`SetPath`.
- Compile per-family independence: v4 block set, v6 unset ⇒ only
  `Dhcp4` carries the block.
- Schema: `set ... expired-leases-processing ?` completion lists the
  six leaves; commit-check rejects a non-integer; a timer < 1 rejects
  (Min(1)) while a cap of 0 is accepted (Min(0), 0=unlimited — pins the
  MAJOR-3 floor split); value-slot `?` shows the placeholder + examples.
- Stored-config tolerance: a stored config with the block loads on the
  lenient path even if a validator later tightens (H7).

**Deploy smoke (standalone or cluster, NOT a new lab venue):**

- `make test-deploy`; commit a DHCP-server config WITH the block; assert
  Kea reconfigures cleanly (`systemctl is-active kea-dhcp4-server`) and
  the generated `/etc/kea/kea-dhcp4.conf` contains the block.
- Hand a lease, let it expire, confirm via the Kea control socket /
  memfile that the row is reclaimed within `reclaim-timer +
  flush-timer + hold-time` (optional, env-permitting; the unit golden
  is the binding gate).
- Negative: a config without the block reconfigures Kea with no
  `expired-leases-processing` key (regression guard for H1 at deploy).

**Lab-deferred (NOT a CI/merge gate for Path S):** none required — Path
S has no DNS dependency. (The DDNS live-lab residue in §1 item 2 stays
separately deferred.)

---

## 11. Out of scope (explicit)

- The DDNS feature (shipped, §1/§4).
- Live DDNS Kea→DNS end-to-end + DDNS-over-failover (terminal
  PLAN-DEFERRED — venue gap).
- kea-d2 alternate backend (PLAN-KILL — §6).
- Per-pool reclamation (invalid in Kea — §6 S+).
- Reading Kea reclamation statistics into xpf metrics (needs the
  control socket; a separate, demand-gated enhancement).
- Touching `valid-lifetime` / per-pool `LeaseTime` (H4 — independent).
- Any new go.mod dependency (Path S is pure config-render).

## 12. Open questions

1. **Empty-`{}` vs omit when enabled-with-no-tuning.** Does Kea
   meaningfully differ between `"expired-leases-processing": {}` and an
   absent key? If identical, prefer emitting `{}` so the operator sees
   the feature is on in the rendered config; if Kea warns on an empty
   block, omit. Resolve from Kea docs at engineer time. (Low; render
   detail.)
2. **Which numeric knobs have a meaningful Kea `0`.** Confirm against
   Kea docs: `max-reclaim-leases` and `max-reclaim-time` are the
   suspected 0=unlimited fields needing set/unset tracking (H2). If the
   timers also accept 0 with non-default meaning, extend the discipline;
   otherwise leave them `>0`-render. (Med; correctness of H2.)
3. **Junos parity vs xpf-native keywords.** Junos has no
   `expired-leases-processing` equivalent (its lease cleanup is
   internal/implicit; `maximum-lease-time` is the closest, and it is a
   *lease-time* knob, not a reclamation knob — H4). So this block is an
   **xpf-native subtree**, consistent with how xpf already exposes
   Kea-native concepts the issue's Open-Question 4 anticipated. Keyword
   spellings chosen to be self-describing rather than copying Kea's
   verbose `*-timer-wait-time` names — confirm the chosen short forms
   read well in `?` help. (Low; naming.)
4. **kea-d2 reserved enum.** Keep the `backend kea-d2` enum value +
   WARN as-is (no runtime). Confirmed PLAN-KILL for building it (§6);
   the question is only whether to *remove* the reserved enum. Keep it —
   it documents the considered-and-deferred alternative and the WARN
   already tells an operator it is inert. (Low.)
