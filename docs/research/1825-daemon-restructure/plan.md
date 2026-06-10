# #1825 — pkg/daemon package-subdir restructure: research plan

## 1. Status

`DRAFT v3 — round-2: AGY PLAN-READY(D) confirmed; Codex PLAN-NEEDS-REVISION
on one residual comment-only citation in the §5.2 cross-caller list,
fixed in v3. Claude SMR PLAN-READY(D). Pending Codex round-3 confirmation.`

Research-only (`/research`). No production code on this branch. The
recommendation below is **Option D (PLAN-KILL)** with a narrowly scoped
opportunistic fallback (Option C-lite) documented for the record.

## 2. Issue framing

#1825 is the §9 residue of the #1669 deep-review triage: evaluate splitting
`pkg/daemon`'s flat file layout into internal subpackages (`ha/`, `neighbor/`,
`apply/`, `linkmgmt/`), weighing Go internal-package boundary mechanics and
the import-cycle topology with `pkg/grpcapi`/`pkg/api`/`pkg/cli` (the
`runtime_probes.go` structural-mirroring precedent exists precisely because
daemon imports those packages, not vice versa). #1669's own triage hedged:
*"highest-value **if pursued**"* and *"PLAN-KILL acceptable if the
Daemon-as-interface seam proves infeasible."* This document answers whether
the seam is feasible and whether the restructure is churn-positive at all.

## 3. Honest scope/value framing

This is a pure-modularity proposal. There is **no performance, correctness,
or operator-visible payoff** — the win, if any, is navigability and
encapsulation for future contributors. At absolute scale:

- **Zero external pressure.** `pkg/daemon` has exactly **one** importer:
  `cmd/xpfd/main.go`, which consumes exactly **three** identifiers
  (`daemon.New`, `daemon.Options`, `daemon.CleanupFabricIPVLANs`). The
  package is already de-facto internal with a 3-identifier public surface.
  Internal subpackages would add encapsulation that no consumer can observe.
- **The project's own modularity rule is not tripped.** The refactoring
  audit (`docs/refactoring-audit-current.txt`, regenerated after #1745)
  contains **zero** `pkg/daemon` entries. The largest file, `daemon_run.go`
  at 1,417 LOC, is below even the 1,500-LOC `[WATCH]` threshold.
  `docs/engineering-style.md`'s modularity discipline is file-LOC- and
  responsibility-based; nothing in pkg/daemon violates it. The #1661
  large-file-split backlog (addendum-3 covered `daemon_run.go`/`daemon_ha.go`
  file splits) is closed and the well is dry.
- **File-count flatness is already mitigated by naming discipline.** The 30
  production files carry consistent cluster prefixes (`daemon_ha_*`,
  `daemon_neighbor_*`, `host_tunables*`, `rss_*`); ripgrep/gopls/goto-def
  navigate it without friction.

*If reviewers conclude the gain is too small to justify the churn, PLAN-KILL
is an acceptable verdict.* (Here, it is the recommended verdict.)

## 4. What's already shipped / partially batched

- **`pkg/daemon/system/` exists** (extracted in #1713, `235e4429d`):
  `dns.go` + `dns_test.go`, 302 LOC of free functions (resolved drop-in
  rendering). This is the working precedent for *organic* extraction: a
  self-contained, free-function, single-responsibility cluster left the flat
  package when a feature change touched it — not as a standalone
  restructure project.
- **`runtime_probes.go` (#1519, sub-#1451 S4)**: the daemon→api/grpcapi/cli
  import direction is load-bearing. Daemon constructs `api.Config`,
  `grpcapi.Config`, and `cli.New(...)` values; the consumers keep their
  runtime surfaces package-private and daemon mirrors them structurally.
  Any subpackage split must keep `daemon → {api,grpcapi,cli}` edges intact
  and must not force those packages to import daemon subpackages (cycle).
- **#1661 addendum-3** already did the file-level splits this package
  needed; both former offenders are now sub-watch-threshold.

## 5. Concrete design (inventory, clusters, and the structural blocker)

### 5.1 Inventory (origin/master `d30cfab84`, 2026-06-10)

71 `.go` files, 23,376 total LOC. Production: **30 files, 14,263 LOC**.
Tests: 41 files, ~9,113 LOC (all in `package daemon`, many exercising
unexported identifiers). The issue title's "65 files, ~22K LOC" has already
grown by 6 files since filing — the package is hot.

Natural clusters (production LOC):

| Cluster | Files | LOC | Daemon-method density |
|---|---|---|---|
| run/lifecycle | daemon.go, daemon_run.go, daemon_health.go, daemon_gc.go, daemon_scheduler.go, exec_timeout.go, runtime_probes.go | ~2,275 | mixed; daemon_run is the composition root |
| ha/vip/fabric | daemon_ha.go, daemon_ha_userspace.go, daemon_ha_sync.go, daemon_ha_fabric.go, daemon_ha_vip.go, rg_state.go, daemon_cluster_bind.go, daemon_reth.go | ~5,418 | 92 `(d *Daemon)` methods; rg_state/reth/cluster_bind are free funcs |
| apply/config | daemon_apply.go, daemon_flow.go, daemon_dns.go, daemon_nft.go, daemon_ra.go, daemon_system.go, daemon_forwarding_status.go | ~3,129 | 36 methods |
| neighbor | daemon_neighbor.go, daemon_neighbor_listener.go | 1,079 | 18 methods |
| host/link tuning | linksetup.go, host_tunables.go, host_tunables_daemon.go, rss_indirection.go, coalescence.go | ~2,147 | mostly free funcs (3 methods in host_tunables_daemon.go) |
| dhcp glue | daemon_dhcp.go | 215 | 3 methods |

### 5.2 The structural blocker: Daemon is a 116-field god object

- `type Daemon struct` (daemon.go:66-324) has **116 fields**.
- **167 methods** on `*Daemon` across ~25 of the 30 production files
  (receiver-uniform: every one is spelled `func (d *Daemon)`; verified
  with a receiver-name-agnostic match). The only other method-bearing
  type of note is `*rgStateMachine` (20 methods, self-contained in
  `rg_state.go`) — the exception that proves the rule.
- **269 distinct unexported selector spellings** (`\bd\.<lowerIdent>`)
  across the production sources (272 total including 3 exported
  Daemon-receiver selectors: `d.RefreshFabricFwd`,
  `d.CompileHealthSnapshot`, `d.NeighborPeriodicPhaseAges`).

Go forbids defining methods on a type outside its defining package.
Therefore **no Daemon-method file can move to a subpackage as a file move**.
Each moved cluster requires one of:

(a) **God-object decomposition** — carve the 116 fields into per-cluster
sub-structs (`ha.State`, `neighbor.State`, ...), convert methods, thread
cross-cluster access through exported accessors or interfaces. This is a
rewrite of essentially all 14K production LOC's selector paths, not a
restructure.

(b) **Daemon-as-interface seam** (the #1669 §9 sketch) — subpackages accept
a `Daemon`-shaped interface. Measured against the most "cohesive" candidate,
the neighbor cluster: its 2 files touch **35 distinct `d.*` members** —
~12 Daemon fields spanning 7+ unrelated subsystems (`d.cluster`, `d.dhcp`,
`d.dp`, `d.store`, `d.neighborProvider`, `d.regenDebouncer`,
`d.fabricMu`/`d.fabricOverlay`/`d.fabricOverlay1`/`d.fabricPeerIP`/
`d.fabricPeerIP1`, `d.startTime`), ~10 guard atomics, and cross-cluster
method calls in **both directions**: apply/ha_vip/health/run call 6
unexported neighbor methods (`resolveNeighbors` — daemon_apply.go:834,
daemon_ha_vip.go; `forceProbeNeighbors` — daemon_ha_vip.go:178;
`resolveNeighborsInner` — daemon_health.go:84;
`maintainClusterNeighborReadiness` — daemon_health.go:85;
`runPeriodicNeighborResolution` — daemon_run.go:742;
`neighborListener` wiring — daemon_run.go; mentions in daemon_ha.go:367
and daemon.go:109/127 are comment-only and excluded),
while neighbor methods call back into regen (`d.triggerRegen`,
`d.shouldTriggerRegen`) and into **HA** (`d.warmNeighborCache()` at
daemon_neighbor.go:551 is *defined in daemon_ha.go:1081*). The interface
seam for the *easiest* cluster is ~20 methods wide and bidirectional. The
HA cluster (92 methods, the heaviest) is strictly worse.

Measurement note (round-1 corrections): selector counts use
word-boundary-anchored grep; comment-only mentions are excluded from the
cross-caller lists (`collectNeighborProbeTargets` is internal to the
neighbor cluster — its sole non-comment external "reference" was a
comment in daemon_apply.go:801). The per-file cross-reference counts in
the Option C table are grep-derived **upper bounds** that may include
comment mentions; treat them as sizing, not exact export lists.

(c) **internal/ leaf extraction of free-function files only** — the only
mechanically honest variant; sized in Option C below.

### 5.3 Import topology (verified)

- Importers of `pkg/daemon`: `cmd/xpfd/main.go` only.
- `pkg/daemon` imports 28 internal packages, including `pkg/api`,
  `pkg/grpcapi`, `pkg/cli`. Subpackages under `pkg/daemon/internal/...`
  would sit at the same DAG depth — they may import `api`/`grpcapi`/`cli`
  but nothing may import them back. No inversion is *forced* by Option C;
  Option A/B variants that move the `Daemon` type itself risk cycles the
  moment a subpackage needs the parent type (parent imports child for
  composition; child cannot name `*daemon.Daemon`).

### 5.4 Churn / conflict exposure (verified)

- **263 commits** touched `pkg/daemon` since 2026-03-01. Hottest files in
  the last ~5 weeks: `daemon_run.go` (18 commits), `daemon.go` (12),
  `daemon_apply.go` (11), `daemon_ha_sync.go` (7), `daemon_dns.go` (7),
  `daemon_neighbor.go` (5), `daemon_dhcp.go` (5).
- **In-flight work that lands in these exact files**: PR #1835 (Kea
  authoritative — `daemon_apply.go`), PR #1832 (DHCP renew), the #1800
  sweep umbrella (11 plan-ready units; the heartbeat/PrivateRGElection/
  RestartHeartbeat units live in `daemon_ha*.go`), and #1782 PR-2
  (neighbor files, capture-gated). A restructure now would force rebases
  across every one of them.

## 6. Public API preservation

Trivially satisfiable under every option: the public surface is
`daemon.New`, `daemon.Options`, `daemon.CleanupFabricIPVLANs` (plus
incidental exported types referenced by `Options`). All options preserve
these verbatim. This is also the strongest argument that subpackage
*encapsulation* buys nothing: there is no consumer to protect.

## 7. Hidden invariants any restructure must preserve

- **runtime_probes structural mirroring**: `apiDataPlane`/`grpcDataPlane`/
  `cliDataPlane` must keep compiling against `api.Config.DP`,
  `grpcapi.Config.DP`, `cli.New` assignment sites. Moving the probes or the
  composition root into a subpackage must not invert the
  daemon→{api,grpcapi,cli} import direction.
- **Test access to unexported state**: 41 test files live in `package
  daemon` and reach unexported fields/methods (e.g.
  `host_tunables_restore_test.go` constructs `Daemon` directly;
  `neighbor_periodic_guard_test.go` drives unexported loop internals; the
  synthetic canary tests re-declare local `Daemon` shapes). Any move
  forces test relocation + export widening or `export_test.go` shims.
- **HA ordering invariants**: `daemon_ha*.go` encodes failover sequencing
  (sync-hold release, VIP reconciliation, fabric redirect setup) where
  call order across "clusters" (ha→neighbor→apply) is load-bearing
  (#1769/#1771/#1780 history). Mechanical moves are safe; seam
  introduction (interfaces, split structs with separate mutexes) is where
  regressions would hide.
- **git-blame/`git log --follow` continuity** for incident archaeology —
  this package is the subject of active forensic work (#1782 overnight
  captures reference daemon_neighbor history).

## 8. Risk assessment

| Risk class | Option A (full internal/ split) | Option B (prefix renames) | Option C (1-2 leaf extractions) | Option D (kill) |
|---|---|---|---|---|
| Behavioral regression | **HIGH** — 167 method conversions, seam mutexes, ordering | LOW (rename-only) | LOW-MED (free-func moves; host_tunables has 3 Daemon methods to re-seam) | none |
| Import-cycle / compile-shape | **MED-HIGH** — parent/child type cycles around `*Daemon` | none | LOW (leaf-only, no parent type crossing) | none |
| Performance regression | LOW (control plane; interface indirection negligible here) | none | none | none |
| Architectural mismatch | **HIGH** — god-object decomposition disguised as a file move; #1669 §9's own kill-hedge | n/a (no architecture) | LOW but value≈0 (audit dry) | n/a |
| Merge-conflict exposure vs #1800/#1782/#1832/#1835 | **SEVERE** (touches every in-flight daemon file) | MED (renames conflict with every open patch hunk header) | LOW-MED (leaf files are colder) | none |
| git-blame damage | SEVERE (moves + identifier renames defeat content tracking) | MED (`--follow` works, content intact) | LOW-MED (whole-file moves, `--follow` works) | none |

## 9. Path options with honest cost table

### Option A — full `pkg/daemon/internal/{ha,neighbor,apply,linkmgmt}` split

The #1669 §9 sketch. **Costs**: god-object decomposition of 116 fields;
conversion of up to 167 methods; export/rename churn across 269 unexported
selector spellings; bidirectional seams (neighbor alone needs ~20 exported
entry points + accessors); 41 test files relocated; multi-PR series
(realistically 6-10 PRs / weeks of reviewer time) colliding with all
in-flight daemon work; blame history shredded. **Benefit**: compiler-
enforced boundaries... protecting a package with one importer and three
public identifiers. **Verdict: reject.** The "Daemon-as-interface seam" is
feasible in the trivial sense but is a rewrite, and #1669 pre-authorized
the kill for exactly this finding.

### Option B — file-prefix discipline only

**Costs**: pure rename churn; every open PR hunk conflicts; blame friction.
**Benefit**: ~zero — the prefix discipline **already exists** (`daemon_ha_*`,
`daemon_neighbor_*`, `host_tunables*`, `rss_*`, `coalescence*`). At most
2-3 files have non-obvious names (`rg_state.go`, `linksetup.go`,
`exec_timeout.go`), and each is well-known. **Verdict: reject as a
project.** (Renaming an oddly named file *while already modifying it* is
ordinary hygiene, not this issue.)

### Option C — extract 1-2 genuinely free-standing leaf clusters, then stop

The only mechanically honest variant. Candidates ranked by measured
coupling (unexported top-level identifiers defined / referenced by other
daemon files — each cross-reference becomes an exported identifier +
call-site rename):

| Candidate | LOC (prod+test) | unexported ids / referenced elsewhere | Test coupling to Daemon |
|---|---|---|---|
| `host_tunables*.go` → `internal/hosttunables` | 1,025 + 836 | 19 / **11** | restore test constructs Daemon (6 refs) — needs shim |
| `rss_indirection.go` + `coalescence.go` → `internal/nictune` | 765 + 1,146 | 15 / 6 | none (0 Daemon refs) |
| `rg_state.go` → `internal/rgstate` | 365 + 929 | 7 / 3 | none |
| `linksetup.go` | 357 | 14 / 2 | n/a |
| `daemon_reth.go` | 331 | 12 / **9** | — too entangled, skip |
| `daemon_dhcp.go` | 215 | narrowest seam: only **9** `d.*` members, 3 methods | — too small to justify a package; pure helpers (`resolveJunosIfName`, `stripCIDR`) are shared with the neighbor cluster |

Caveat on `internal/nictune` (round-1 correction): it is **not**
zero-coupling. `applyCoalescence` takes `*priorHostTunables`
(coalescence.go:55) and captures `mlx5CoalesceState` (coalescence.go:110),
both defined in host_tunables.go (:549, :580); host-tunables restore
depends back on `rssExecutor`/`isExecNotFound` (host_tunables.go:672,
:776). Extracting nictune alone forces type hoisting or dragging the
whole host_tunables cluster along — the real unit is the combined
~2,147-LOC host/link cluster, at the top of the cost range above.

**Costs**: per extraction, ~5-15 identifier exports + call-site renames, a
test-file move, one PR each through quad review. **Benefit**: ~2-3K LOC
leaves the flat directory; daemon drops to ~25 prod files. **Honest
assessment**: this solves no diagnosed problem — the audit is dry, no file
is over watch threshold, navigation is not impaired — so even the cheap
variant is churn for churn's sake *as a standalone project*. The `system/`
precedent (#1713) shows the right trigger: extract opportunistically when
feature work is already in the file. **Verdict: viable but not
recommended as scheduled work.**

### Option D — PLAN-KILL: flat-71 is fine

Close #1825 with the `plan-kill` label and this rationale:

1. Methods-on-Daemon make the proposed `ha/`/`neighbor/`/`apply/`
   subpackages a god-object rewrite, not a restructure (Go's
   cross-package-method prohibition; 167 methods, 116 fields, 269
   selector spellings, bidirectional cluster coupling).
2. The package has one importer and three public identifiers — internal
   boundaries add unobservable encapsulation.
3. The project's own modularity rule (file-LOC, responsibility) flags
   nothing in pkg/daemon; the #1661 well is declared dry.
4. Conflict exposure against #1800 (11 units, HA files), #1782 PR-2
   (neighbor files), #1832/#1835 (dhcp/apply) is maximal right now.
5. Standing guidance replaces the project: future extractions follow the
   `pkg/daemon/system` precedent — opportunistic, free-function leaf
   clusters only, when feature work already touches them; never move
   `(d *Daemon)` methods across a package boundary.

**Verdict: recommended.**

## 10. Test plan

For Option D (recommended): none — no code changes. For the record, any
revived Option C extraction would gate on: `make build` clean, full
`make test` (30 Go packages), `go vet`, plus the standard smoke (v4+v6
iperf3 on `loss:xpf-userspace-fw0/fw1`) and `make test-failover` if any
HA-adjacent file moves — and per-PR quad review under `/engineer`.

## 11. Out of scope (explicitly)

- The §10/§11 siblings (`pkg/grpcapi`, `pkg/cli` package restructures) —
  separate issues if ever pursued; their coupling shape differs (server
  structs, not a 116-field god object) so this kill does not auto-apply.
- Any file-level split of individual daemon files that later cross the
  2,000-LOC audit threshold — that is the standing audit's job.
- God-object decomposition of `Daemon` for its own sake (no issue asks
  for it; if one is ever filed it must be motivated by a concrete defect
  class, e.g. mutex-scope bugs, not aesthetics).
- Renaming oddly named files during unrelated work (ordinary hygiene).

## 12. Open questions for adversarial review

1. Is there a defect class (not aesthetics) that flat-71 demonstrably
   causes — e.g. evidence of wrong-file edits, missed-review coupling, or
   mutex-scope bugs traceable to the layout? If yes, KILL is wrong.
2. Does the Daemon-as-interface seam have a cheaper variant the SMR
   missed — e.g. moving only *leaf callees* (pure functions called by
   methods) rather than the methods themselves, achieving most of the
   navigability win at Option-C cost?
3. Is the neighbor-cluster coupling measurement (35 `d.*` members,
   bidirectional calls) representative, or is there a cluster with a
   genuinely narrow seam that was overlooked (dhcp glue at 215 LOC /
   3 methods)?
4. Option C's "no diagnosed problem" claim — do reviewers accept that a
   dry audit means no scheduled extraction, or should `internal/nictune`
   (zero Daemon coupling in tests, 6 cross-refs) ship anyway as a
   low-cost wedge that establishes the layout for future organic moves?
5. Is the conflict-exposure argument durable? #1800/#1782 will eventually
   land — is "do it later when the in-flight queue drains" more honest
   than KILL, i.e. should this close as deferred rather than killed?
6. The kill rationale leans on "one importer, three identifiers." If a
   future consumer (e.g. a test harness or a second binary) needed daemon
   internals, would flat-71 with 269 unexported spellings become a real
   cost — and does that change the verdict today?
